# SPDX-License-Identifier: MIT
"""Dump small AE function ranges used for targeted relocation review."""

from __future__ import print_function

import json
import os
from pathlib import Path

import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import idautils
import idc


REPO_ROOT = Path(__file__).resolve().parents[1]


OUTPUT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
RANGES = (
    ("localized_strings", 0x351700, 0x351B00),
    ("console_log", 0x103A000, 0x103AA00),
    ("console_log_methods", 0x103BC00, 0x103C300),
    ("tes_condition", 0x768E00, 0x769100),
)


def clean(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return ida_lines.tag_remove(str(value or ""))


def decompile(ea):
    try:
        return clean(ida_hexrays.decompile(ea))
    except Exception as error:
        return "<decompile failed: {}>".format(error)


def main():
    imagebase = ida_nalt.get_imagebase()
    rows = []
    for label, start_rva, end_rva in RANGES:
        for ea in idautils.Functions(imagebase + start_rva, imagebase + end_rva):
            function = ida_funcs.get_func(ea)
            if function is None:
                continue
            rows.append(
                {
                    "range": label,
                    "rva": "0x{:X}".format(ea - imagebase),
                    "size": function.end_ea - function.start_ea,
                    "name": clean(idc.get_name(ea, idc.GN_VISIBLE)),
                    "pseudocode": decompile(ea),
                }
            )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / "targeted_ae_function_ranges.json"
    output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print("Wrote {}".format(output))
    idc.qexit(0)


if __name__ == "__main__":
    main()
