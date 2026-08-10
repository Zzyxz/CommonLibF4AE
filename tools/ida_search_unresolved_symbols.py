# SPDX-License-Identifier: MIT
"""Read-only IDA name search for the remaining special CommonLib symbols."""

from __future__ import print_function

import csv
import os
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
OUTPUT_PATH = OUTPUT_DIR / "ae_unresolved_symbol_name_search.csv"
PATTERNS = [
    "type_info",
    "name_internal_method",
    "defaultobjectdata",
    "flatscreenmodel",
    "gamesettingcollection",
    "inisettingcollection",
    "iniprefsettingcollection",
    "sparsefullname",
    "fullname",
]


try:
    import idaapi
    import ida_kernwin
    import ida_nalt
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_kernwin = None
    ida_nalt = None
    idautils = None
    idc = None


def main():
    if idautils is None:
        raise RuntimeError("Dieses Skript muss innerhalb von IDA laufen")
    imagebase = int(ida_nalt.get_imagebase())
    rows = []
    for ea, name in idautils.Names():
        ea = int(ea)
        raw_name = str(name or "")
        try:
            demangled = idc.demangle_name(raw_name, idc.get_inf_attr(idc.INF_SHORT_DN)) or ""
        except Exception:
            demangled = ""
        searchable = (raw_name + " " + str(demangled)).lower().replace("_", "")
        for pattern in PATTERNS:
            if pattern.replace("_", "") not in searchable:
                continue
            rows.append(
                {
                    "pattern": pattern,
                    "rva": "0x{:X}".format(ea - imagebase),
                    "ea": "0x{:X}".format(ea),
                    "name": raw_name,
                    "demangled": demangled,
                    "segment": str(idc.get_segm_name(ea) or ""),
                }
            )
    rows.sort(key=lambda row: (row["pattern"], int(row["rva"], 16)))
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["pattern", "rva", "ea", "name", "demangled", "segment"],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(rows)
    print("[CommonLibF4AE] unresolved symbol name hits={}".format(len(rows)))
    print("[CommonLibF4AE] output={}".format(OUTPUT_PATH))
    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    main()
