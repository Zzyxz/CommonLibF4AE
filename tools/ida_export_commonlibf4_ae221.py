# SPDX-License-Identifier: MIT
"""Read-only Fallout 4 AE 1.11.221 RTTI/VTable/NiRTTI exporter for IDA 9.1.

The script scans the currently opened Fallout4.exe IDA database.  It does not
rename items, add types, patch bytes, or otherwise modify the database.  The
only files it writes are reports and generated headers below OUTPUT_DIR.

The existing function CSV is used as a fallback address -> REL::ID map.  If a
version-1-11-221-0.bin Address Library file is available, set
ADDRESS_LIBRARY_PATH; that file also resolves RTTI/NiRTTI data addresses.

RELOCATION_KIND:
  "auto"   use REL::ID where the map contains an address, otherwise REL::Offset
  "id"     emit only entries with an Address Library/CSV ID
  "offset" emit fixed AE RVAs as REL::Offset

Generated files:
  RTTI_IDs.h, VTABLE_IDs.h, NiRTTI_IDs.h
  rtti_report.csv, nirtti_candidates.csv, missing_rel_ids.csv
  export_summary.txt

MIT License
Copyright (c) 2026 Thomas / CommonLibF4AE contributors
"""

from __future__ import print_function

import csv
import ctypes
import os
import re
import struct
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# User configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = Path(
    os.environ.get(
        "CLF4_SEMANTIC_CSV",
        str(REPO_ROOT / "tools" / "inputs" / "IDA_Functions_OG_163_and_AE_221.csv"),
    )
)
ADDRESS_LIBRARY_PATH = (
    Path(os.environ["CLF4_AE_ADDRESS_LIBRARY"])
    if os.environ.get("CLF4_AE_ADDRESS_LIBRARY")
    else None
)
KNOWN_NIRTTI_HEADER = REPO_ROOT / "CommonLibF4" / "include" / "RE" / "NiRTTI_IDs.h"
OUTPUT_DIR = Path(
    os.environ.get("CLF4_AE_HEADER_EXPORT", str(REPO_ROOT / "build" / "ida-ae221-export"))
)

RELOCATION_KIND = "auto"
MAX_VTABLE_SLOTS = 512
EMIT_UNLISTED_NIRTTI = True


try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_nalt
    import idautils
    import idc
except ImportError:  # Allows py_compile/linting outside IDA.
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_kernwin = None
    ida_nalt = None
    idautils = None
    idc = None


BADADDR = getattr(idc, "BADADDR", 0xFFFFFFFFFFFFFFFF) if idc else 0xFFFFFFFFFFFFFFFF


def require_ida():
    if idautils is None or ida_bytes is None or ida_nalt is None or idc is None:
        raise RuntimeError("Dieses Skript muss innerhalb von IDA 9.1 ausgeführt werden.")


def clean_text(value):
    if isinstance(value, bytes):
        return value.split(b"\0", 1)[0].decode("utf-8", "replace")
    return str(value or "")


def parse_hex(value):
    value = clean_text(value).strip()
    if not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def parse_decimal(value):
    value = clean_text(value).strip()
    if not value:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def load_csv_map(path):
    """Return AE RVA -> REL ID and the original CSV rows by function name."""
    rva_to_id = {}
    rows_by_name = {}
    if not path.is_file():
        return rva_to_id, rows_by_name

    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            name = clean_text(row.get("Name", "")).strip()
            if name:
                rows_by_name[name] = row
            rva = parse_hex(row.get("AE_221_Addr", ""))
            rel_id = parse_decimal(row.get("AE_221_REL_ID", ""))
            if rva is not None and rel_id is not None:
                rva_to_id[rva] = rel_id
    return rva_to_id, rows_by_name


def load_address_library(path):
    """Read REL's count + {uint64 id, uint64 offset} mapping format."""
    if path is None or not path.is_file():
        return {}

    raw = path.read_bytes()
    if len(raw) < 8:
        raise RuntimeError("Address Library Datei ist zu klein: {}".format(path))

    count = struct.unpack_from("<Q", raw, 0)[0]
    expected = 8 + count * 16
    if expected > len(raw):
        raise RuntimeError(
            "Address Library Datei ist beschädigt: {} Einträge angekündigt, {} Bytes vorhanden".format(
                count, len(raw)
            )
        )

    offset_to_id = {}
    for index in range(count):
        rel_id, offset = struct.unpack_from("<QQ", raw, 8 + index * 16)
        offset_to_id[offset] = rel_id
    return offset_to_id


class RelocationLookup:
    def __init__(self, csv_map, address_library):
        self.csv_map = csv_map
        self.address_library = address_library

    def id_for_rva(self, rva):
        if rva in self.address_library:
            return self.address_library[rva]
        return self.csv_map.get(rva)


def segment_ranges():
    ranges = []
    for start in idautils.Segments():
        end = idc.get_segm_end(start)
        if end <= start:
            continue
        name = clean_text(idc.get_segm_name(start) or "")
        ranges.append((start, end, name))
    return ranges


def selected_ranges(ranges, accepted):
    accepted = tuple(item.lower() for item in accepted)
    result = []
    for start, end, name in ranges:
        lower = name.lower()
        if any(lower == item or lower.startswith(item + ".") for item in accepted):
            result.append((start, end, name))
    return result


def in_ranges(ea, ranges):
    return any(start <= ea < end for start, end, _name in ranges)


def iter_aligned(ranges, alignment):
    for start, end, _name in ranges:
        current = (start + alignment - 1) & ~(alignment - 1)
        while current + alignment <= end:
            yield current
            current += alignment


def qword(ea):
    return ida_bytes.get_qword(ea)


def dword(ea):
    return ida_bytes.get_dword(ea)


def load_ida_strings():
    result = {}
    for item in idautils.Strings():
        try:
            text = clean_text(str(item))
            ea = int(item.ea)
        except Exception:
            continue
        if text:
            result[ea] = text
    return result


def sanitize_name(name):
    """Match the historical RTTIDump name transformation."""
    name = clean_text(name)
    name = name.replace("`anonymous namespace'", "")
    for character in " &'*-`":
        name = name.replace(character, "")
    for character in "(),:<>":
        name = name.replace(character, "_")
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name:
        name = "anonymous"
    if name[0].isdigit():
        name = "_" + name
    return name


def load_known_nirtti_names(path):
    if path is None or not path.is_file():
        return set()
    result = set()
    pattern = re.compile(r"inline\s+constexpr\s+REL::(?:ID|Offset)\s+([A-Za-z_]\w*)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            result.add(match.group(1))
    return result


def is_msvc_rtti_string(text):
    return text.startswith(".?A") and len(text) >= 7 and text.endswith("@@")


_undecorate_symbol_name = None


def undecorate_msvc_name(name):
    global _undecorate_symbol_name
    if _undecorate_symbol_name is False:
        return None
    if _undecorate_symbol_name is None:
        try:
            function = ctypes.WinDLL("dbghelp.dll").UnDecorateSymbolName
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
            function.restype = ctypes.c_uint32
            _undecorate_symbol_name = function
        except Exception:
            _undecorate_symbol_name = False
            return None

    flags = (
        0x0002  # UNDNAME_NO_MS_KEYWORDS
        | 0x0004  # UNDNAME_NO_FUNCTION_RETURNS
        | 0x0008  # UNDNAME_NO_ALLOCATION_MODEL
        | 0x0010  # UNDNAME_NO_ALLOCATION_LANGUAGE
        | 0x0060  # UNDNAME_NO_THISTYPE
        | 0x0080  # UNDNAME_NO_ACCESS_SPECIFIERS
        | 0x0100  # UNDNAME_NO_THROW_SIGNATURES
        | 0x0400  # UNDNAME_NO_RETURN_UDT_MODEL
        | 0x1000  # UNDNAME_NAME_ONLY
        | 0x2000  # UNDNAME_NO_ARGUMENTS
        | 0x8000  # suppress enum/class/struct/union prefix
    )
    buffer = ctypes.create_string_buffer(0x10000)
    length = _undecorate_symbol_name(name.encode("ascii", "replace"), buffer, len(buffer), flags)
    if not length:
        return None
    return buffer.value.decode("mbcs", "replace")


def decode_msvc_rtti_name(text):
    """Best-effort decoder for MSVC TypeDescriptor strings."""
    text = clean_text(text)
    if not is_msvc_rtti_string(text):
        return None

    undecorated = undecorate_msvc_name(text[1:])
    if undecorated:
        return undecorated

    # Keep IDA and the raw parser as fallbacks.  TypeDescriptor stores the
    # leading dot form, whereas the demanglers expect the string after it.
    if idc is not None:
        for candidate in (text[1:] if text.startswith(".") else text, text, "?" + text[3:]):
            try:
                demangled = idc.demangle_name(candidate, idc.get_inf_attr(idc.INF_SHORT_DN))
            except Exception:
                demangled = None
            if demangled:
                demangled = clean_text(demangled)
                if demangled:
                    return demangled

    body = text[4:-2]  # .?AV + name + @@
    parts = [part for part in body.split("@") if part]
    if not parts:
        return None
    return "::".join(reversed(parts))


def plausible_type_descriptor(ea, text, metadata_ranges):
    if not in_ranges(ea, metadata_ranges):
        return False
    # The first 0x10 bytes are the type_info vftable/spare pointer.  The
    # mangled name starts directly at +0x10 and is not another pointer.
    return bool(text)


def valid_complete_object_locator(col, td_rva, rdata_ranges):
    if not in_ranges(col, rdata_ranges) or col + 0x14 > max(end for _start, end, _name in rdata_ranges):
        return False
    if dword(col + 0x0C) != td_rva:
        return False
    if dword(col) not in (0, 1):
        return False

    class_desc = dword(col + 0x10)
    class_desc_ea = imagebase_global + class_desc
    if not in_ranges(class_desc_ea, rdata_ranges):
        return False
    base_count = dword(class_desc_ea + 0x08)
    base_array = dword(class_desc_ea + 0x0C)
    if base_count == 0 or base_count > 512:
        return False
    if not in_ranges(imagebase_global + base_array, rdata_ranges):
        return False
    return True


def is_code_address(ea, code_ranges):
    if not ea or ea == BADADDR:
        return False
    if in_ranges(ea, code_ranges):
        return True
    try:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            return True
        return ida_funcs.get_func(ea) is not None
    except Exception:
        return False


def scan_vtable_slots(vtable_ea, code_ranges):
    slots = []
    for index in range(MAX_VTABLE_SLOTS):
        function_ea = qword(vtable_ea + index * 8)
        if not is_code_address(function_ea, code_ranges):
            break
        slots.append(function_ea)
    return slots


def discover_rtti(strings, ranges, imagebase):
    metadata_ranges = selected_ranges(ranges, (".rdata", "rdata", ".data", "data"))
    rdata_ranges = selected_ranges(ranges, (".rdata", "rdata")) or metadata_ranges
    code_ranges = selected_ranges(ranges, (".text", "text", ".code", "code"))

    descriptors = {}
    for string_ea, text in strings.items():
        if not is_msvc_rtti_string(text):
            continue
        descriptor_ea = string_ea - 0x10
        name = decode_msvc_rtti_name(text)
        if name and plausible_type_descriptor(descriptor_ea, text, metadata_ranges):
            descriptors[descriptor_ea] = {
                "name": name,
                "key": sanitize_name(name),
                "rva": descriptor_ea - imagebase,
                "cols": [],
                "vtables": [],
            }

    by_td_rva = {entry["rva"] & 0xFFFFFFFF: (descriptor_ea, entry) for descriptor_ea, entry in descriptors.items()}
    col_to_descriptors = defaultdict(list)

    # The x64 CompleteObjectLocator stores TypeDescriptor and class descriptor
    # as image-relative uint32 RVAs.  This mirrors RTTIDump's runtime scan.
    for address in iter_aligned(rdata_ranges, 4):
        target = by_td_rva.get(dword(address))
        if target is None:
            continue
        descriptor_ea, entry = target
        col = address - 0x0C
        if not valid_complete_object_locator(col, dword(address), rdata_ranges):
            continue
        if col not in entry["cols"]:
            entry["cols"].append(col)
        col_to_descriptors[col].append(entry)

    all_metadata = metadata_ranges or rdata_ranges
    for pointer_ea in iter_aligned(all_metadata, 8):
        pointed_to = qword(pointer_ea)
        if pointed_to not in col_to_descriptors:
            continue
        vtable_ea = pointer_ea + 8
        slots = scan_vtable_slots(vtable_ea, code_ranges)
        if not slots:
            continue
        for entry in col_to_descriptors[pointed_to]:
            if not any(item["ea"] == vtable_ea for item in entry["vtables"]):
                entry["vtables"].append({"ea": vtable_ea, "slots": slots})

    for entry in descriptors.values():
        entry["cols"].sort()
        entry["vtables"].sort(key=lambda item: item["ea"])
    return list(descriptors.values())


GET_RTTI_SUFFIX = "::GetRTTI(void)"
DYNAMIC_NIRTTI_PREFIX = "_dynamic_initializer_for__"
DYNAMIC_NIRTTI_SUFFIX = "::ms_RTTI__"


def normalize_nirtti_key(class_name, known_names):
    class_name = clean_text(class_name).replace("`anonymous namespace'::", "")
    full = sanitize_name(class_name)
    if full in known_names:
        return full

    # A few engine namespaces are omitted from the historical NiRTTI names,
    # e.g. NVFlex::DebrisNode -> DebrisNode.
    parts = class_name.split("::")
    for index in range(1, len(parts)):
        suffix = sanitize_name("::".join(parts[index:]))
        if suffix in known_names:
            return suffix
    return full


def returned_data_target(function_ea, data_ranges):
    """Resolve the object returned by a tiny GetRTTI() function."""
    function = ida_funcs.get_func(function_ea)
    if function is None:
        return None

    current_ea = function.start_ea
    followed = set()
    for _depth in range(4):
        if current_ea in followed:
            break
        followed.add(current_ea)

        function = ida_funcs.get_func(current_ea)
        if function is None:
            break
        for item in idautils.FuncItems(function.start_ea):
            if item - function.start_ea > 0x40:
                break
            for target in idautils.DataRefsFrom(item):
                if in_ranges(target, data_ranges) and target % 8 == 0:
                    return target

        mnemonic = clean_text(idc.print_insn_mnem(function.start_ea)).lower()
        if mnemonic != "jmp":
            break
        target = idc.get_operand_value(function.start_ea, 0)
        if target in (0, BADADDR):
            break
        current_ea = target
    return None


def initialized_nirtti_target(function_ea, data_ranges):
    """Resolve the RCX object argument passed by a dynamic NiRTTI initializer."""
    function = ida_funcs.get_func(function_ea)
    if function is None:
        return None
    for item in idautils.FuncItems(function.start_ea):
        if item - function.start_ea > 0x40:
            break
        if clean_text(idc.print_insn_mnem(item)).lower() != "lea":
            continue
        if clean_text(idc.print_operand(item, 0)).lower() != "rcx":
            continue
        target = idc.get_operand_value(item, 1)
        if in_ranges(target, data_ranges) and target % 8 == 0:
            return target
    return None


def discover_nirtti(ranges, imagebase, known_names, rows_by_name, rtti_entries):
    # AE initializes most NiRTTI objects in the zero-filled part of .data.
    # Consequently their name/base pointers are not present in the raw IDB.
    # GetRTTI() functions still return the final object address directly.
    data_ranges = selected_ranges(ranges, (".data", "data"))
    if not data_ranges:
        data_ranges = selected_ranges(ranges, (".rdata", "rdata"))

    resolved = {}

    def add_candidate(class_name, key, target, source, function_ea=None, function_rel_id=None):
        if target is None:
            return
        candidate = {
            "ea": target,
            "rva": target - imagebase,
            "name": class_name,
            "key": key,
            "known": key in known_names,
            "source": source,
            "source_function_ea": function_ea,
            "source_function_rel_id": function_rel_id,
        }
        previous = resolved.get(key)
        if previous is None or (previous["source"] != "getrtti_csv" and source == "getrtti_csv"):
            resolved[key] = candidate

    for function_name, row in rows_by_name.items():
        if not function_name.endswith(GET_RTTI_SUFFIX):
            continue
        function_rva = parse_hex(row.get("AE_221_Addr", ""))
        if function_rva is None:
            continue
        class_name = function_name[: -len(GET_RTTI_SUFFIX)].replace("`anonymous namespace'::", "")
        key = normalize_nirtti_key(class_name, known_names)
        if key not in known_names and not EMIT_UNLISTED_NIRTTI:
            continue
        function_ea = imagebase + function_rva
        add_candidate(
            class_name,
            key,
            returned_data_target(function_ea, data_ranges),
            "getrtti_csv",
            function_ea,
            parse_decimal(row.get("AE_221_REL_ID", "")),
        )

    # Some NiRTTI-only helper classes have no matched GetRTTI function.  Their
    # dynamic initializer passes the zero-filled object's address in RCX.
    for function_name, row in rows_by_name.items():
        if not function_name.startswith(DYNAMIC_NIRTTI_PREFIX):
            continue
        marker = function_name.find(DYNAMIC_NIRTTI_SUFFIX, len(DYNAMIC_NIRTTI_PREFIX))
        if marker < 0:
            continue
        function_rva = parse_hex(row.get("AE_221_Addr", ""))
        if function_rva is None:
            continue
        class_name = function_name[len(DYNAMIC_NIRTTI_PREFIX) : marker]
        key = normalize_nirtti_key(class_name, known_names)
        if key in resolved or (key not in known_names and not EMIT_UNLISTED_NIRTTI):
            continue
        function_ea = imagebase + function_rva
        add_candidate(
            class_name,
            key,
            initialized_nirtti_target(function_ea, data_ranges),
            "dynamic_initializer",
            function_ea,
            parse_decimal(row.get("AE_221_REL_ID", "")),
        )

    # Recover classes whose GetRTTI function was not matched in the OG/AE CSV.
    # NiObject-derived classes keep GetRTTI at virtual slot 2.
    unresolved = known_names.difference(resolved)
    for key in sorted(unresolved):
        matching_rtti = [
            entry
            for entry in rtti_entries
            if entry["key"] == key or entry["key"].endswith("__" + key)
        ]
        found = False
        for entry in matching_rtti:
            for vtable in entry["vtables"]:
                if len(vtable["slots"]) <= 2:
                    continue
                function_ea = vtable["slots"][2]
                target = returned_data_target(function_ea, data_ranges)
                if target is None:
                    continue
                add_candidate(entry["name"], key, target, "vtable_slot_2", function_ea, None)
                found = True
                break
            if found:
                break

    emitted = [
        candidate
        for candidate in resolved.values()
        if candidate["known"] or EMIT_UNLISTED_NIRTTI
    ]
    report = list(emitted)
    for key in sorted(known_names.difference(resolved)):
        report.append(
            {
                "ea": None,
                "rva": None,
                "name": key,
                "key": key,
                "known": True,
                "source": "unresolved",
                "source_function_ea": None,
                "source_function_rel_id": None,
            }
        )
    return emitted, report


def choose_kind(items, lookup):
    if RELOCATION_KIND not in {"auto", "id", "offset"}:
        raise RuntimeError("RELOCATION_KIND muss auto, id oder offset sein")
    if RELOCATION_KIND == "offset":
        return "offset"
    if RELOCATION_KIND == "id":
        return "id"
    return "id" if all(lookup.id_for_rva(item["rva"]) is not None for item in items) else "offset"


def relocation_expression(rva, rel_id, kind):
    if kind == "id":
        if rel_id is None:
            return None
        return "REL::ID({})".format(rel_id)
    return "REL::Offset(0x{:X})".format(rva)


def header_open(namespace):
    return (
        "#pragma once\n"
        "\n"
        "// Generated read-only from the user's Fallout 4 AE 1.11.221 IDA database.\n"
        "// Do not edit manually; rerun tools/ida_export_commonlibf4_ae221.py.\n"
        "\n"
        "namespace RE\n"
        "{\n"
        "\tnamespace "
        + namespace
        + "\n"
        + "\t{\n"
    )


def write_rtti_header(path, entries, lookup):
    by_name = {}
    for entry in entries:
        by_name.setdefault(entry["key"], entry)
    lines = [header_open("RTTI")]
    for name in sorted(by_name):
        entry = by_name[name]
        rel_id = lookup.id_for_rva(entry["rva"])
        kind = choose_kind([entry], lookup)
        expression = relocation_expression(entry["rva"], rel_id, kind)
        if expression is not None:
            lines.append("\t\tinline constexpr auto {}{{ {} }};\n".format(name, expression))
    lines.extend(["\t}\n", "}\n"])
    path.write_text("".join(lines), encoding="utf-8", newline="\n")


def write_vtable_header(path, entries, lookup):
    selected = {}
    for entry in entries:
        if not entry["vtables"]:
            continue
        previous = selected.get(entry["key"])
        score = (len(entry["vtables"]), sum(len(item["slots"]) for item in entry["vtables"]), -entry["rva"])
        if previous is None or score > previous[0]:
            selected[entry["key"]] = (score, entry)

    lines = [header_open("VTABLE")]
    for name in sorted(selected):
        _score, entry = selected[name]
        vtables = entry["vtables"]
        relocation_items = [{"rva": item["ea"] - imagebase_global} for item in vtables]
        kind = choose_kind(relocation_items, lookup)
        expressions = []
        for vtable in vtables:
            rva = vtable["ea"] - imagebase_global
            rel_id = lookup.id_for_rva(rva)
            expression = relocation_expression(rva, rel_id, kind)
            if expression is not None:
                expressions.append(expression)
        if RELOCATION_KIND == "id" and len(expressions) != len(vtables):
            continue
        if expressions:
            lines.append(
                "\t\tinline constexpr std::array<REL::{}, {}> {}{{ {} }};\n".format(
                    "ID" if kind == "id" else "Offset", len(expressions), name, ", ".join(expressions)
                )
            )
    lines.extend(["\t}\n", "}\n"])
    path.write_text("".join(lines), encoding="utf-8", newline="\n")


def write_nirtti_header(path, entries, lookup):
    by_name = {}
    for entry in entries:
        by_name.setdefault(entry["key"], entry)
    lines = [header_open("Ni_RTTI")]
    for name in sorted(by_name):
        entry = by_name[name]
        rel_id = lookup.id_for_rva(entry["rva"])
        kind = choose_kind([entry], lookup)
        expression = relocation_expression(entry["rva"], rel_id, kind)
        if expression is not None:
            lines.append("\t\tinline constexpr auto {}{{ {} }};\n".format(name, expression))
    lines.extend(["\t}\n", "}\n"])
    path.write_text("".join(lines), encoding="utf-8", newline="\n")


def write_csv(path, fieldnames, rows):
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_reports(output_dir, rtti_entries, nirtti_entries, all_nirtti, lookup, imagebase):
    missing = []
    rtti_rows = []
    for entry in sorted(rtti_entries, key=lambda item: item["key"]):
        rel_id = lookup.id_for_rva(entry["rva"])
        if rel_id is None:
            missing.append(
                {
                    "kind": "RTTI",
                    "name": entry["key"],
                    "slot": "",
                    "ea": "0x{:X}".format(entry["rva"] + imagebase),
                    "rva": "0x{:X}".format(entry["rva"]),
                    "rel_id": "",
                }
            )

        vtable_rvas = []
        missing_vtables = []
        for index, vtable in enumerate(entry["vtables"]):
            rva = vtable["ea"] - imagebase
            vtable_rvas.append("0x{:X}".format(rva))
            if lookup.id_for_rva(rva) is None:
                missing_vtables.append("0x{:X}".format(rva))
                missing.append(
                    {
                        "kind": "VTABLE",
                        "name": entry["key"],
                        "slot": index,
                        "ea": "0x{:X}".format(vtable["ea"]),
                        "rva": "0x{:X}".format(rva),
                        "rel_id": "",
                    }
                )
        rtti_rows.append(
            {
                "name": entry["name"],
                "key": entry["key"],
                "rtti_ea": "0x{:X}".format(entry["rva"] + imagebase),
                "rtti_rva": "0x{:X}".format(entry["rva"]),
                "rtti_rel_id": "" if rel_id is None else str(rel_id),
                "col_count": len(entry["cols"]),
                "vtable_count": len(entry["vtables"]),
                "vtable_rvas": ",".join(vtable_rvas),
                "missing_vtable_rvas": ",".join(missing_vtables),
            }
        )

    nirtti_rows = []
    for candidate in sorted(all_nirtti, key=lambda item: (item["ea"] is None, item["ea"] or 0, item["key"])):
        rva = candidate["rva"]
        rel_id = lookup.id_for_rva(rva) if rva is not None else None
        if rva is not None and rel_id is None:
            missing.append(
                {
                    "kind": "NiRTTI",
                    "name": candidate["key"],
                    "slot": "",
                    "ea": "0x{:X}".format(candidate["ea"]),
                    "rva": "0x{:X}".format(rva),
                    "rel_id": "",
                }
            )
        nirtti_rows.append(
            {
                "name": candidate["name"],
                "key": candidate["key"],
                "ea": "0x{:X}".format(candidate["ea"]) if candidate["ea"] is not None else "",
                "rva": "0x{:X}".format(rva) if rva is not None else "",
                "rel_id": "" if rel_id is None else str(rel_id),
                "source": candidate["source"],
                "source_function_ea": (
                    "0x{:X}".format(candidate["source_function_ea"])
                    if candidate["source_function_ea"] is not None
                    else ""
                ),
                "source_function_rel_id": candidate["source_function_rel_id"] or "",
                "known_header_name": "yes" if candidate.get("known") else "no",
                "emitted": "yes" if candidate in nirtti_entries else "no",
            }
        )

    write_csv(
        output_dir / "rtti_report.csv",
        [
            "name",
            "key",
            "rtti_ea",
            "rtti_rva",
            "rtti_rel_id",
            "col_count",
            "vtable_count",
            "vtable_rvas",
            "missing_vtable_rvas",
        ],
        rtti_rows,
    )
    write_csv(
        output_dir / "nirtti_candidates.csv",
        [
            "name",
            "key",
            "ea",
            "rva",
            "rel_id",
            "source",
            "source_function_ea",
            "source_function_rel_id",
            "known_header_name",
            "emitted",
        ],
        nirtti_rows,
    )
    write_csv(
        output_dir / "missing_rel_ids.csv",
        ["kind", "name", "slot", "ea", "rva", "rel_id"],
        missing,
    )
    return missing


def main():
    global imagebase_global
    require_ida()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    imagebase_global = ida_nalt.get_imagebase()
    csv_map, rows_by_name = load_csv_map(CSV_PATH)
    address_library = load_address_library(ADDRESS_LIBRARY_PATH)
    lookup = RelocationLookup(csv_map, address_library)
    ranges = segment_ranges()
    strings = load_ida_strings()
    known_nirtti = load_known_nirtti_names(KNOWN_NIRTTI_HEADER)

    if ida_kernwin:
        ida_kernwin.show_wait_box("HIDECANCEL Erzeuge AE-RTTI/VTable/NiRTTI-Export ...")
    try:
        rtti_entries = discover_rtti(strings, ranges, imagebase_global)
        nirtti_entries, all_nirtti = discover_nirtti(
            ranges,
            imagebase_global,
            known_nirtti,
            rows_by_name,
            rtti_entries,
        )

        write_rtti_header(OUTPUT_DIR / "RTTI_IDs.h", rtti_entries, lookup)
        write_vtable_header(OUTPUT_DIR / "VTABLE_IDs.h", rtti_entries, lookup)
        write_nirtti_header(OUTPUT_DIR / "NiRTTI_IDs.h", nirtti_entries, lookup)
        missing = write_reports(
            OUTPUT_DIR,
            rtti_entries,
            nirtti_entries,
            all_nirtti,
            lookup,
            imagebase_global,
        )

        summary = [
            "Fallout 4 AE 1.11.221 IDA export",
            "Read-only database scan: yes",
            "Image base: 0x{:X}".format(imagebase_global),
            "IDA strings: {}".format(len(strings)),
            "CSV path: {} ({})".format(CSV_PATH, "found" if CSV_PATH.is_file() else "missing"),
            "CSV AE RVA -> ID entries: {}".format(len(csv_map)),
            "Address Library: {} ({})".format(
                ADDRESS_LIBRARY_PATH or "not configured",
                "found" if address_library else "not loaded",
            ),
            "Address Library RVA -> ID entries: {}".format(len(address_library)),
            "MSVC RTTI descriptors: {}".format(len(rtti_entries)),
            "NiRTTI candidates: {} (emitted: {})".format(len(all_nirtti), len(nirtti_entries)),
            "Generated VTable entries: see VTABLE_IDs.h",
            "Missing ID rows: {}".format(len(missing)),
            "Relocation kind: {}".format(RELOCATION_KIND),
            "Output directory: {}".format(OUTPUT_DIR),
        ]
        if not address_library:
            summary.append(
                "HINWEIS: Ohne version-1-11-221-0.bin fallen nicht in der CSV enthaltene Datenadressen auf REL::Offset zurück."
            )
        (OUTPUT_DIR / "export_summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
        for line in summary:
            print("[CommonLibF4AE] " + line)
    finally:
        if ida_kernwin:
            ida_kernwin.hide_wait_box()

    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    main()
