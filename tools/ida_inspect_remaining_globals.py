# SPDX-License-Identifier: MIT
"""Read-only IDA 9.1 inspection for the last CommonLibF4 AE globals."""

from __future__ import print_function

import json
import os
from pathlib import Path

try:
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import idaapi
    import idautils
    import idc
except ImportError:
    ida_bytes = None
    ida_funcs = None
    ida_hexrays = None
    ida_nalt = None
    idaapi = None
    idautils = None
    idc = None


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)

TARGET_RVAS = {
    "default_object_data_old_id_continuity": 0x2ED9F90,
    "flat_screen_model_vtable": 0x2525800,
    "flat_screen_model_process_event": 0x9A9D60,
    "tes_full_name_get_length": 0x315CE0,
    "tes_full_name_get_name": 0x315DD0,
    "memory_manager_reallocate_candidate": 0x1657D20,
    "ini_setting_init_collection": 0x22D5F0,
    "ini_pref_setting_init_collection": 0x2DDA90,
    "game_setting_constructor": 0x22D510,
}

NAME_PATTERNS = (
    "flatscreenmodel",
    "defaultobject",
    "default_object",
    "fullname",
    "sparsefullname",
)


def clean(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def rva(ea, imagebase):
    return ea - imagebase


def ea_record(ea, imagebase):
    return {
        "ea": "0x{:X}".format(ea),
        "rva": "0x{:X}".format(rva(ea, imagebase)),
        "name": clean(idc.get_name(ea, idc.GN_VISIBLE)),
        "segment": clean(idc.get_segm_name(ea)),
    }


def xref_records(target_ea, imagebase):
    records = []
    for xref in idautils.XrefsTo(target_ea, 0):
        item = ea_record(xref.frm, imagebase)
        function = ida_funcs.get_func(xref.frm)
        item.update(
            {
                "xref_type": int(xref.type),
                "is_code": bool(xref.iscode),
                "function_ea": "0x{:X}".format(function.start_ea) if function else "",
                "function_rva": "0x{:X}".format(rva(function.start_ea, imagebase)) if function else "",
                "function_name": clean(idc.get_func_name(function.start_ea)) if function else "",
                "instruction": clean(idc.generate_disasm_line(xref.frm, 0)),
            }
        )
        records.append(item)
    return records


def decompile_function(start_ea):
    if ida_hexrays is None:
        return ""
    try:
        return clean(ida_hexrays.decompile(start_ea))
    except Exception as error:
        return "<decompile failed: {}>".format(error)


def function_record(start_ea, imagebase):
    function = ida_funcs.get_func(start_ea)
    if function is None:
        return None
    data_refs = []
    code_refs = []
    instructions = []
    for ea in idautils.FuncItems(function.start_ea):
        instruction = clean(idc.generate_disasm_line(ea, 0))
        instructions.append(
            {
                "ea": "0x{:X}".format(ea),
                "rva": "0x{:X}".format(rva(ea, imagebase)),
                "text": instruction,
            }
        )
        for target in idautils.DataRefsFrom(ea):
            item = ea_record(target, imagebase)
            item.update(
                {
                    "from_ea": "0x{:X}".format(ea),
                    "from_rva": "0x{:X}".format(rva(ea, imagebase)),
                    "instruction": instruction,
                }
            )
            data_refs.append(item)
        for target in idautils.CodeRefsFrom(ea, False):
            item = ea_record(target, imagebase)
            item.update(
                {
                    "from_ea": "0x{:X}".format(ea),
                    "from_rva": "0x{:X}".format(rva(ea, imagebase)),
                    "instruction": instruction,
                }
            )
            code_refs.append(item)
    return {
        "start_ea": "0x{:X}".format(function.start_ea),
        "start_rva": "0x{:X}".format(rva(function.start_ea, imagebase)),
        "end_ea": "0x{:X}".format(function.end_ea),
        "name": clean(idc.get_func_name(function.start_ea)),
        "data_refs": data_refs,
        "code_refs": code_refs,
        "instructions": instructions,
        "pseudocode": decompile_function(function.start_ea),
    }


def named_matches(imagebase):
    result = []
    for ea, name in idautils.Names():
        lower = clean(name).lower()
        patterns = [pattern for pattern in NAME_PATTERNS if pattern in lower]
        if patterns:
            item = ea_record(ea, imagebase)
            item["patterns"] = patterns
            result.append(item)
    return result


def main():
    if idautils is None or ida_nalt is None or idc is None:
        raise RuntimeError("This script must run inside IDA 9.1")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    imagebase = ida_nalt.get_imagebase()

    targets = []
    function_starts = set()
    for label, target_rva in TARGET_RVAS.items():
        target_ea = imagebase + target_rva
        item = ea_record(target_ea, imagebase)
        item["label"] = label
        item["xrefs"] = xref_records(target_ea, imagebase)
        raw = ida_bytes.get_bytes(target_ea, 64) if ida_bytes else None
        item["first_64_bytes"] = raw.hex() if raw else ""
        targets.append(item)
        function = ida_funcs.get_func(target_ea)
        if function:
            function_starts.add(function.start_ea)
        for xref in item["xrefs"]:
            if xref["function_ea"]:
                function_starts.add(int(xref["function_ea"], 16))

    names = named_matches(imagebase)
    for item in names:
        function = ida_funcs.get_func(int(item["ea"], 16))
        if function and any(
            pattern in clean(item["name"]).lower()
            for pattern in ("flatscreenmodel", "fullname", "defaultobject")
        ):
            function_starts.add(function.start_ea)

    functions = []
    for start_ea in sorted(function_starts):
        record = function_record(start_ea, imagebase)
        if record:
            functions.append(record)

    report = {
        "imagebase": "0x{:X}".format(imagebase),
        "read_only": True,
        "targets": targets,
        "named_matches": names,
        "functions": functions,
    }
    output = OUTPUT_DIR / "remaining_globals_targeted_inspection.json"
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    summary = [
        "Fallout 4 AE 1.11.221 remaining globals targeted inspection",
        "Read-only database scan: yes",
        "Image base: 0x{:X}".format(imagebase),
        "Targets: {}".format(len(targets)),
        "Named matches: {}".format(len(names)),
        "Functions exported: {}".format(len(functions)),
        "JSON: {}".format(output),
    ]
    summary_path = OUTPUT_DIR / "remaining_globals_targeted_inspection_summary.txt"
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
    for line in summary:
        print("[CommonLibF4AE] " + line)

    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    main()
