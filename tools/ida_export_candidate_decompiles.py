# SPDX-License-Identifier: MIT
"""Export read-only OG/AE pseudocode evidence for unresolved relocations."""

from __future__ import print_function

import csv
import json
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

try:
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_lines
    import ida_nalt
    import idaapi
    import idautils
    import idc
except ImportError:
    ida_bytes = None
    ida_funcs = None
    ida_hexrays = None
    ida_lines = None
    ida_nalt = None
    idaapi = None
    idautils = None
    idc = None


REPORT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
INPUT_CSV = REPORT_DIR / "official_current_commonlib_ae_relocations.csv"
SIDE = os.environ.get("CLF4_IDA_SIDE", "").strip().lower()


def clean(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value or "")
    return ida_lines.tag_remove(text) if ida_lines is not None else text


def integer(value):
    text = clean(value).strip()
    return int(text, 0) if text else None


def address_record(ea, imagebase):
    return {
        "rva": "0x{:X}".format(ea - imagebase),
        "name": clean(idc.get_name(ea, idc.GN_VISIBLE)),
        "segment": clean(idc.get_segm_name(ea)),
    }


def decompile(start_ea):
    if ida_hexrays is None:
        return ""
    try:
        return clean(ida_hexrays.decompile(start_ea))
    except Exception as error:
        return "<decompile failed: {}>".format(error)


def nearest_named_item(ea, max_distance=0x2000):
    current = ea
    minimum = max(0, ea - max_distance)
    while current != idc.BADADDR and current >= minimum:
        name = clean(idc.get_name(current, idc.GN_VISIBLE))
        if name:
            return current, name
        previous = idc.prev_head(current, minimum)
        if previous == idc.BADADDR or previous >= current:
            break
        current = previous
    return None, ""


def inspect_function(target_ea, imagebase):
    function = ida_funcs.get_func(target_ea)
    if function is None:
        return {"status": "not_a_function"}
    calls = []
    data_refs = []
    strings = []
    instructions = []
    for ea in idautils.FuncItems(function.start_ea):
        instruction = clean(idc.generate_disasm_line(ea, 0))
        instructions.append(instruction)
        for target in idautils.CodeRefsFrom(ea, False):
            item = address_record(target, imagebase)
            item["from_rva"] = "0x{:X}".format(ea - imagebase)
            calls.append(item)
        for target in idautils.DataRefsFrom(ea):
            item = address_record(target, imagebase)
            item["from_rva"] = "0x{:X}".format(ea - imagebase)
            data_refs.append(item)
            value = idc.get_strlit_contents(target, -1, idc.STRTYPE_C)
            if value:
                strings.append(clean(value))
    callers = []
    incoming_data_refs = []
    for xref in idautils.XrefsTo(function.start_ea, 0):
        if not xref.iscode:
            owner_ea, owner_name = nearest_named_item(xref.frm)
            incoming_data_refs.append(
                {
                    "from_rva": "0x{:X}".format(xref.frm - imagebase),
                    "segment": clean(idc.get_segm_name(xref.frm)),
                    "owner_rva": (
                        "0x{:X}".format(owner_ea - imagebase)
                        if owner_ea is not None
                        else ""
                    ),
                    "owner_name": owner_name,
                    "slot": (
                        (xref.frm - owner_ea) // 8
                        if owner_ea is not None and xref.frm >= owner_ea
                        else ""
                    ),
                }
            )
            continue
        caller = ida_funcs.get_func(xref.frm)
        if caller:
            callers.append(address_record(caller.start_ea, imagebase))
    return {
        "status": "ok",
        "start_rva": "0x{:X}".format(function.start_ea - imagebase),
        "end_rva": "0x{:X}".format(function.end_ea - imagebase),
        "size": function.end_ea - function.start_ea,
        "name": clean(idc.get_func_name(function.start_ea)),
        "type": clean(idc.get_type(function.start_ea)),
        "pseudocode": decompile(function.start_ea),
        "instructions": instructions,
        "calls": calls,
        "data_refs": data_refs,
        "strings": sorted(set(strings)),
        "callers": callers,
        "incoming_data_refs": incoming_data_refs,
    }


def inspect_global(target_ea, imagebase):
    raw = ida_bytes.get_bytes(target_ea, 64) if ida_bytes is not None else None
    xrefs = []
    for xref in idautils.XrefsTo(target_ea, 0):
        item = address_record(xref.frm, imagebase)
        function = ida_funcs.get_func(xref.frm)
        item.update(
            {
                "is_code": bool(xref.iscode),
                "function_rva": "0x{:X}".format(function.start_ea - imagebase) if function else "",
                "function_name": clean(idc.get_func_name(function.start_ea)) if function else "",
                "instruction": clean(idc.generate_disasm_line(xref.frm, 0)),
            }
        )
        xrefs.append(item)
    result = address_record(target_ea, imagebase)
    result.update(
        {
            "status": "ok",
            "first_64_bytes": raw.hex() if raw else "",
            "xrefs": xrefs,
        }
    )
    return result


def main():
    if SIDE not in {"og", "ae221"}:
        raise RuntimeError("Set CLF4_IDA_SIDE to og or ae221")
    if idautils is None or ida_nalt is None or idc is None:
        raise RuntimeError("This script must run inside IDA 9.1")

    imagebase = ida_nalt.get_imagebase()
    with INPUT_CSV.open("r", encoding="utf-8-sig", newline="") as source:
        candidates = [
            row
            for row in csv.DictReader(source, delimiter=";")
            if row.get("confidence_tier") in {"medium", "review"}
            and row.get("existing_ae_id_status") != "match"
        ]

    output = REPORT_DIR / "candidate_decompiles_{}.jsonl".format(SIDE)
    with output.open("w", encoding="utf-8", newline="\n") as target:
        metadata = {
            "kind": "metadata",
            "side": SIDE,
            "imagebase": "0x{:X}".format(imagebase),
            "candidate_count": len(candidates),
            "read_only": True,
        }
        target.write(json.dumps(metadata, ensure_ascii=False) + "\n")
        for row in candidates:
            target_rva = integer(row["og_rva"] if SIDE == "og" else row["ae_rva"])
            target_ea = imagebase + target_rva
            evidence = (
                inspect_function(target_ea, imagebase)
                if row["kind"] == "function"
                else inspect_global(target_ea, imagebase)
            )
            record = {
                "kind": row["kind"],
                "side": SIDE,
                "og_id": int(row["og_id"]),
                "official_ae_id": int(row["official_ae_id"]),
                "symbol_name": row["symbol_name"],
                "confidence_tier": row["confidence_tier"],
                "match_evidence": row["evidence"],
                "target_rva": "0x{:X}".format(target_rva),
                "evidence": evidence,
            }
            target.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = [
        "Candidate decompile export",
        "Side: {}".format(SIDE),
        "Read-only database scan: yes",
        "Candidates: {}".format(len(candidates)),
        "Output: {}".format(output),
    ]
    summary_path = REPORT_DIR / "candidate_decompiles_{}_summary.txt".format(SIDE)
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
    for line in summary:
        print("[CommonLibF4AE] " + line)

    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    main()
