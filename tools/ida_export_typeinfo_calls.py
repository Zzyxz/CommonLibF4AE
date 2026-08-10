# SPDX-License-Identifier: MIT
"""Export AE callsites around __std_type_info_name to locate its root node."""

from __future__ import print_function

import csv
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
OUTPUT_PATH = OUTPUT_DIR / "ae_typeinfo_name_calls.csv"
TARGET_NAMES = ["__imp___std_type_info_name", "__std_type_info_name"]


try:
    import idaapi
    import ida_funcs
    import ida_nalt
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_nalt = None
    idautils = None
    idc = None


def main():
    if idautils is None:
        raise RuntimeError("Dieses Skript muss innerhalb von IDA laufen")
    imagebase = int(ida_nalt.get_imagebase())
    rows = []
    for target_name in TARGET_NAMES:
        target_ea = int(idc.get_name_ea_simple(target_name))
        if target_ea == int(idc.BADADDR):
            continue
        for xref in idautils.XrefsTo(target_ea, 0):
            source_ea = int(xref.frm)
            function = ida_funcs.get_func(source_ea)
            function_name = str(idc.get_name(function.start_ea) or "") if function else ""
            cursor = source_ea
            context = []
            for _index in range(12):
                previous = int(idc.prev_head(cursor))
                if previous == int(idc.BADADDR) or (function and previous < int(function.start_ea)):
                    break
                cursor = previous
                refs = []
                for ref in idautils.DataRefsFrom(cursor):
                    ref = int(ref)
                    refs.append(
                        "0x{:X}:{}".format(ref - imagebase, str(idc.get_name(ref) or ""))
                    )
                context.append(
                    "0x{:X} {} [{}]".format(
                        cursor - imagebase,
                        str(idc.generate_disasm_line(cursor, 0) or ""),
                        ",".join(refs),
                    )
                )
            context.reverse()
            rows.append(
                {
                    "target_name": target_name,
                    "target_rva": "0x{:X}".format(target_ea - imagebase),
                    "xref_type": int(xref.type),
                    "source_rva": "0x{:X}".format(source_ea - imagebase),
                    "function_rva": "" if not function else "0x{:X}".format(int(function.start_ea) - imagebase),
                    "function_name": function_name,
                    "source_disasm": str(idc.generate_disasm_line(source_ea, 0) or ""),
                    "previous_context": " | ".join(context),
                }
            )
    with OUTPUT_PATH.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "target_name",
                "target_rva",
                "xref_type",
                "source_rva",
                "function_rva",
                "function_name",
                "source_disasm",
                "previous_context",
            ],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(rows)
    print("[CommonLibF4AE] type_info call/xref rows={}".format(len(rows)))
    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    main()
