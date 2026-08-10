# SPDX-License-Identifier: MIT
"""Dump selected OG/AE vtable slots from an IDA database (read-only)."""

from __future__ import print_function

import json
import os
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_nalt
import idaapi
import idc


REPO_ROOT = Path(__file__).resolve().parents[1]


SIDE = os.environ.get("CLF4_IDA_SIDE", "").strip().lower()
OUTPUT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
VTABLES = (
    "??_7ReaderStream@Archive2@BSResource@@6B@",
    "??_7AsyncReaderStream@Archive2@BSResource@@6B@",
    "??_7PipboySubMenu@@6B@",
    "??_7PipboyPlayerInfoMenu@@6B@",
    "??_7GameMenuBase@@6BSWFToCodeFunctionHandler@@@",
    "AE::GameMenuBase[0]",
    "AE::GameMenuBase[1]",
)
FALLBACK_RVAS = {
    ("ae221", "AE::GameMenuBase[0]"): 0x252EE18,
    ("ae221", "AE::GameMenuBase[1]"): 0x252EEC0,
}


def clean(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value or "")


def main():
    if SIDE not in ("og", "ae221"):
        raise RuntimeError("Set CLF4_IDA_SIDE to og or ae221")

    imagebase = ida_nalt.get_imagebase()
    rows = []
    for vtable_name in VTABLES:
        vtable_ea = idc.get_name_ea_simple(vtable_name)
        if vtable_ea == idaapi.BADADDR:
            fallback_rva = FALLBACK_RVAS.get((SIDE, vtable_name))
            if fallback_rva is not None:
                vtable_ea = imagebase + fallback_rva
        entry = {
            "side": SIDE,
            "vtable_name": vtable_name,
            "vtable_rva": (
                "0x{:X}".format(vtable_ea - imagebase)
                if vtable_ea != idaapi.BADADDR
                else ""
            ),
            "slots": [],
        }
        if vtable_ea != idaapi.BADADDR:
            for slot in range(32):
                target_ea = ida_bytes.get_qword(vtable_ea + slot * 8)
                function = ida_funcs.get_func(target_ea)
                start_ea = function.start_ea if function else target_ea
                entry["slots"].append(
                    {
                        "slot": slot,
                        "target_rva": "0x{:X}".format(target_ea - imagebase),
                        "function_rva": "0x{:X}".format(start_ea - imagebase),
                        "name": clean(idc.get_name(start_ea, idc.GN_VISIBLE)),
                    }
                )
        rows.append(entry)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / "selected_vtables_{}.json".format(SIDE)
    output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print("Wrote {}".format(output))
    idc.qexit(0)


if __name__ == "__main__":
    main()
