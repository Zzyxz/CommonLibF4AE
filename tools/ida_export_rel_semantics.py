# SPDX-License-Identifier: MIT
"""Export comparable Fallout 4 function semantics from an IDA 9.1 database.

The exporter is intentionally read-only with respect to the IDA database.  It
uses the existing OG 1.10.163 <-> AE 1.11.221 CSV as an index and emits one
JSON object per complete ID pair.  Both databases therefore produce the same
row keys and can be compared without relying on IDA names alone.

Environment variables:
  CLF4_IDA_SIDE       og or ae221 (normally inferred from the IDB path)
  CLF4_SEMANTIC_CSV   mapping CSV path
  CLF4_SEMANTIC_OUT   output directory

Run once for the OG IDB and once for the AE IDB.  The companion
compare_rel_semantics.py script creates the human-readable reports.

MIT License
Copyright (c) 2026 Thomas / CommonLibF4AE contributors
"""

from __future__ import print_function

import csv
import hashlib
import json
import os
import re
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


CSV_PATH = Path(
    os.environ.get(
        "CLF4_SEMANTIC_CSV",
        str(REPO_ROOT / "tools" / "inputs" / "IDA_Functions_OG_163_and_AE_221.csv"),
    )
)
OUTPUT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
SIDE_OVERRIDE = os.environ.get("CLF4_IDA_SIDE", "").strip().lower()
PROGRESS_INTERVAL = 1000
TARGET_LIMIT = int(os.environ.get("CLF4_SEMANTIC_LIMIT", "0") or "0")
MAX_STRING_LENGTH = 1024
MAX_MEMBER_DISPLACEMENT = 0x10000


try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError:  # Allows py_compile outside IDA.
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_ua = None
    idautils = None
    idc = None


def clean_text(value):
    if isinstance(value, bytes):
        return value.split(b"\0", 1)[0].decode("utf-8", "replace")
    if value is None:
        return ""
    return str(value).replace("\0", "")


def parse_hex(value):
    text = clean_text(value).strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def parse_decimal(value):
    text = clean_text(value).strip()
    if not text:
        return None
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def require_ida():
    if idautils is None or ida_funcs is None or ida_nalt is None or idc is None:
        raise RuntimeError("Dieses Skript muss innerhalb von IDA 9.1 laufen.")


def database_paths():
    paths = []
    try:
        paths.append(clean_text(idc.get_idb_path()))
    except Exception:
        pass
    try:
        paths.append(clean_text(ida_nalt.get_input_file_path()))
    except Exception:
        pass
    return [path for path in paths if path]


def detect_side():
    aliases = {
        "og": "og",
        "163": "og",
        "1.10.163": "og",
        "ae": "ae221",
        "ae221": "ae221",
        "221": "ae221",
        "1.11.221": "ae221",
    }
    if SIDE_OVERRIDE:
        if SIDE_OVERRIDE not in aliases:
            raise RuntimeError("Unbekanntes CLF4_IDA_SIDE: {}".format(SIDE_OVERRIDE))
        return aliases[SIDE_OVERRIDE]

    joined = " ".join(database_paths()).lower()
    if "ae_221" in joined or "ae221" in joined or "1.11.221" in joined:
        return "ae221"
    if "f4_og" in joined or "1.10.163" in joined:
        return "og"
    raise RuntimeError(
        "IDB-Seite nicht erkennbar. CLF4_IDA_SIDE auf 'og' oder 'ae221' setzen."
    )


def load_csv_rows(path):
    if not path.is_file():
        raise RuntimeError("Mapping-CSV fehlt: {}".format(path))

    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row_number, raw in enumerate(csv.DictReader(source, delimiter=";"), start=2):
            row = {
                "row": row_number,
                "name": clean_text(raw.get("Name", "")).strip(),
                "og_rva": parse_hex(raw.get("OG_Addr", "")),
                "og_id": parse_decimal(raw.get("OG_REL_ID", "")),
                "ae_rva": parse_hex(raw.get("AE_221_Addr", "")),
                "ae_id": parse_decimal(raw.get("AE_221_REL_ID", "")),
            }
            rows.append(row)
    return rows


class CsvIndex(object):
    def __init__(self, rows, side):
        self.rows = rows
        self.side = side
        self.rva_key = "og_rva" if side == "og" else "ae_rva"
        self.id_key = "og_id" if side == "og" else "ae_id"
        self.by_rva = defaultdict(list)
        for row in rows:
            rva = row[self.rva_key]
            if rva is not None:
                self.by_rva[rva].append(row)

    def targets(self):
        # Structural comparison is meaningful only when both sides and IDs exist.
        return [
            row
            for row in self.rows
            if row["og_rva"] is not None
            and row["og_id"] is not None
            and row["ae_rva"] is not None
            and row["ae_id"] is not None
        ]

    def rows_for_rva(self, rva):
        return self.by_rva.get(rva, [])


def counter_dict(counter):
    return {clean_text(key): int(value) for key, value in sorted(counter.items())}


def signed_value(value):
    value = int(value) & 0xFFFFFFFFFFFFFFFF
    if value & (1 << 63):
        value -= 1 << 64
    return value


def operand_kind(op_type):
    kinds = {
        getattr(ida_ua, "o_void", 0): "void",
        getattr(ida_ua, "o_reg", 1): "reg",
        getattr(ida_ua, "o_mem", 2): "mem",
        getattr(ida_ua, "o_phrase", 3): "phrase",
        getattr(ida_ua, "o_displ", 4): "displ",
        getattr(ida_ua, "o_imm", 5): "imm",
        getattr(ida_ua, "o_far", 6): "far",
        getattr(ida_ua, "o_near", 7): "near",
    }
    return kinds.get(op_type, "other")


def demangled_name(ea, raw_name):
    try:
        demangled = idc.demangle_name(raw_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled:
            return clean_text(demangled)
    except Exception:
        pass
    try:
        value = idc.get_name(ea, idc.GN_DEMANGLED)
        if value:
            return clean_text(value)
    except Exception:
        pass
    return clean_text(raw_name)


def segment_name(ea):
    try:
        segment = ida_segment.getseg(ea)
        if segment is not None:
            return clean_text(ida_segment.get_segm_name(segment))
    except Exception:
        pass
    try:
        return clean_text(idc.get_segm_name(ea))
    except Exception:
        return ""


def load_strings():
    result = {}
    for item in idautils.Strings():
        try:
            value = clean_text(str(item))[:MAX_STRING_LENGTH]
            if value:
                result[int(item.ea)] = value
        except Exception:
            continue
    return result


def row_reference(row):
    return {
        "row": row["row"],
        "og_id": row["og_id"],
        "ae_id": row["ae_id"],
    }


class SemanticExporter(object):
    def __init__(self, side, csv_index, imagebase, strings):
        self.side = side
        self.csv_index = csv_index
        self.imagebase = imagebase
        self.strings = strings
        self.cache = {}

    def reference(self, ea):
        rva = int(ea) - self.imagebase
        raw_name = clean_text(idc.get_name(ea) or "")
        rows = self.csv_index.rows_for_rva(rva)
        if not rows:
            function = ida_funcs.get_func(ea)
            if function is not None:
                start_rva = int(function.start_ea) - self.imagebase
                rows = self.csv_index.rows_for_rva(start_rva)
        return {
            "rva": rva,
            "name": raw_name,
            "segment": segment_name(ea),
            "csv": [row_reference(row) for row in rows],
        }

    def cfg_metrics(self, function):
        blocks = []
        edge_count = 0
        back_edge_count = 0
        try:
            flowchart = idaapi.FlowChart(function)
            for block in flowchart:
                successors = [int(item.start_ea) for item in block.succs()]
                edge_count += len(successors)
                back_edge_count += sum(1 for ea in successors if ea <= int(block.start_ea))
                blocks.append(
                    {
                        "start_rva": int(block.start_ea) - self.imagebase,
                        "end_rva": int(block.end_ea) - self.imagebase,
                        "successors": [ea - self.imagebase for ea in successors],
                    }
                )
        except Exception:
            pass
        return blocks, edge_count, back_edge_count

    def extract_function(self, requested_ea):
        function = ida_funcs.get_func(requested_ea)
        if function is None:
            return {
                "status": "no_function",
                "requested_rva": int(requested_ea) - self.imagebase,
            }

        start_ea = int(function.start_ea)
        if start_ea in self.cache:
            return self.cache[start_ea]

        raw_name = clean_text(idc.get_name(start_ea) or "")
        mnemonics = Counter()
        signatures = Counter()
        object_displacements = Counter()
        stack_displacements = Counter()
        calls = {}
        jumps = {}
        data_refs = {}
        string_refs = {}
        semantic_hash = hashlib.sha256()
        instruction_count = 0

        for ea in idautils.FuncItems(start_ea):
            ea = int(ea)
            mnemonic = clean_text(idc.print_insn_mnem(ea)).lower()
            if not mnemonic:
                continue
            instruction_count += 1
            mnemonics[mnemonic] += 1

            shapes = []
            for operand_index in range(8):
                op_type = int(idc.get_operand_type(ea, operand_index))
                if op_type == getattr(ida_ua, "o_void", 0):
                    break
                kind = operand_kind(op_type)
                shapes.append(kind)
                if op_type == getattr(ida_ua, "o_displ", 4):
                    value = signed_value(idc.get_operand_value(ea, operand_index))
                    if abs(value) <= MAX_MEMBER_DISPLACEMENT:
                        operand_text = clean_text(idc.print_operand(ea, operand_index)).lower()
                        if "rsp" in operand_text or "rbp" in operand_text:
                            stack_displacements[value] += 1
                        elif "rip" not in operand_text:
                            object_displacements[value] += 1

            signature = "{}:{}".format(mnemonic, ",".join(shapes))
            signatures[signature] += 1
            semantic_hash.update(signature.encode("utf-8", "replace"))
            semantic_hash.update(b"\n")

            for target in idautils.CodeRefsFrom(ea, False):
                target = int(target)
                reference = self.reference(target)
                if mnemonic.startswith("call"):
                    calls[target] = reference
                else:
                    jumps[target] = reference

            for target in idautils.DataRefsFrom(ea):
                target = int(target)
                if target in self.strings:
                    string_refs[target] = {
                        "rva": target - self.imagebase,
                        "text": self.strings[target],
                    }
                else:
                    data_refs[target] = self.reference(target)

        callers = {}
        for source in idautils.CodeRefsTo(start_ea, False):
            source_function = ida_funcs.get_func(int(source))
            source_ea = int(source_function.start_ea) if source_function else int(source)
            callers[source_ea] = self.reference(source_ea)

        incoming_data = {}
        for source in idautils.DataRefsTo(start_ea):
            source = int(source)
            incoming_data[source] = self.reference(source)

        chunks = []
        try:
            chunks = [
                {
                    "start_rva": int(start) - self.imagebase,
                    "end_rva": int(end) - self.imagebase,
                }
                for start, end in idautils.Chunks(start_ea)
            ]
        except Exception:
            chunks = [
                {
                    "start_rva": start_ea - self.imagebase,
                    "end_rva": int(function.end_ea) - self.imagebase,
                }
            ]

        blocks, cfg_edges, cfg_back_edges = self.cfg_metrics(function)
        try:
            type_decl = clean_text(idc.get_type(start_ea) or "")
        except Exception:
            type_decl = ""

        result = {
            "status": "ok",
            "requested_rva": int(requested_ea) - self.imagebase,
            "start_rva": start_ea - self.imagebase,
            "end_rva": int(function.end_ea) - self.imagebase,
            "size": sum(item["end_rva"] - item["start_rva"] for item in chunks),
            "raw_name": raw_name,
            "demangled_name": demangled_name(start_ea, raw_name),
            "type": type_decl,
            "flags": int(getattr(function, "flags", 0)),
            "frame_size": int(getattr(function, "frsize", 0)),
            "saved_register_size": int(getattr(function, "frregs", 0)),
            "argument_size": int(getattr(function, "argsize", 0)),
            "instruction_count": instruction_count,
            "mnemonics": counter_dict(mnemonics),
            "instruction_shapes": counter_dict(signatures),
            "semantic_sha256": semantic_hash.hexdigest(),
            "object_displacements": counter_dict(object_displacements),
            "stack_displacements": counter_dict(stack_displacements),
            "chunk_count": len(chunks),
            "chunks": chunks,
            "basic_block_count": len(blocks),
            "cfg_edge_count": cfg_edges,
            "cfg_back_edge_count": cfg_back_edges,
            "blocks": blocks,
            "calls": [calls[key] for key in sorted(calls)],
            "jumps": [jumps[key] for key in sorted(jumps)],
            "data_refs": [data_refs[key] for key in sorted(data_refs)],
            "strings": [string_refs[key] for key in sorted(string_refs)],
            "callers": [callers[key] for key in sorted(callers)],
            "incoming_data_refs": [incoming_data[key] for key in sorted(incoming_data)],
        }
        self.cache[start_ea] = result
        return result


def base_record(row, side):
    return {
        "kind": "function",
        "row": row["row"],
        "csv_name": row["name"],
        "og_rva": row["og_rva"],
        "og_id": row["og_id"],
        "ae_rva": row["ae_rva"],
        "ae_id": row["ae_id"],
        "side": side,
    }


def main():
    require_ida()
    side = detect_side()
    rows = load_csv_rows(CSV_PATH)
    csv_index = CsvIndex(rows, side)
    targets = csv_index.targets()
    if TARGET_LIMIT > 0:
        targets = targets[:TARGET_LIMIT]
    imagebase = int(ida_nalt.get_imagebase())
    strings = load_strings()
    exporter = SemanticExporter(side, csv_index, imagebase, strings)
    output_path = OUTPUT_DIR / "{}_functions.jsonl".format(side)
    summary_path = OUTPUT_DIR / "{}_summary.txt".format(side)
    error_path = OUTPUT_DIR / "{}_errors.log".format(side)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    started = time.time()
    counts = Counter()
    errors = []
    print("[CommonLibF4AE] Semantic export side={} targets={}".format(side, len(targets)))
    print("[CommonLibF4AE] IDB paths={}".format(" | ".join(database_paths())))
    print("[CommonLibF4AE] Output={}".format(output_path))

    if ida_kernwin:
        ida_kernwin.show_wait_box(
            "HIDECANCEL Exportiere {} Funktionsstrukturen ({}) ...".format(len(targets), side)
        )

    try:
        with output_path.open("w", encoding="utf-8", newline="\n") as output:
            metadata = {
                "kind": "metadata",
                "format": "CommonLibF4-semantic-v1",
                "side": side,
                "imagebase": imagebase,
                "csv": str(CSV_PATH),
                "idb_paths": database_paths(),
                "target_count": len(targets),
            }
            output.write(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")) + "\n")

            rva_key = "og_rva" if side == "og" else "ae_rva"
            for index, row in enumerate(targets, start=1):
                record = base_record(row, side)
                try:
                    requested_ea = imagebase + int(row[rva_key])
                    function = exporter.extract_function(requested_ea)
                    record["function"] = function
                    counts[function.get("status", "unknown")] += 1
                except Exception:
                    counts["error"] += 1
                    message = "CSV row {}: {}\n{}".format(
                        row["row"], row["name"], traceback.format_exc()
                    )
                    errors.append(message)
                    record["function"] = {
                        "status": "error",
                        "message": clean_text(message.splitlines()[-1]),
                    }
                output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

                if index % PROGRESS_INTERVAL == 0 or index == len(targets):
                    elapsed = time.time() - started
                    print(
                        "[CommonLibF4AE] {} {}/{} ({:.1f}%) ok={} no_function={} errors={} elapsed={:.1f}s".format(
                            side,
                            index,
                            len(targets),
                            index * 100.0 / max(1, len(targets)),
                            counts["ok"],
                            counts["no_function"],
                            counts["error"],
                            elapsed,
                        )
                    )
                    output.flush()

        elapsed = time.time() - started
        summary = [
            "CommonLibF4 semantic export",
            "Format: CommonLibF4-semantic-v1",
            "Side: {}".format(side),
            "Read-only IDA scan: yes",
            "Image base: 0x{:X}".format(imagebase),
            "CSV: {}".format(CSV_PATH),
            "Complete OG/AE ID pairs: {}".format(len(targets)),
            "Unique decoded IDA functions: {}".format(len(exporter.cache)),
            "Resolved rows: {}".format(counts["ok"]),
            "Rows without function: {}".format(counts["no_function"]),
            "Errors: {}".format(counts["error"]),
            "IDA strings indexed: {}".format(len(strings)),
            "Elapsed seconds: {:.3f}".format(elapsed),
            "Output: {}".format(output_path),
        ]
        summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
        if errors:
            error_path.write_text("\n\n".join(errors) + "\n", encoding="utf-8", newline="\n")
        elif error_path.exists():
            error_path.unlink()
        for line in summary:
            print("[CommonLibF4AE] " + line)
    finally:
        if ida_kernwin:
            ida_kernwin.hide_wait_box()

    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0 if not errors else 2)


if __name__ == "__main__":
    main()
