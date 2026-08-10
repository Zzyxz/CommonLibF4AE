# SPDX-License-Identifier: MIT
"""Resolve current CommonLib unmapped OG REL IDs to OG RVAs and CSV names."""

from __future__ import print_function

import csv
import os
import struct
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
UNMAPPED_PATH = REPORT_DIR / "current_commonlib_unmapped_rel_ids.csv"
MAPPING_CSV = Path(
    os.environ.get(
        "CLF4_SEMANTIC_CSV",
        str(REPO_ROOT / "tools" / "inputs" / "IDA_Functions_OG_163_and_AE_221.csv"),
    )
)
OG_ADDRESS_LIBRARY = Path(
    os.environ.get(
        "CLF4_OG_ADDRESS_LIBRARY",
        str(REPO_ROOT / "tools" / "inputs" / "version-1-10-163-0.bin"),
    )
)
OUTPUT_PATH = REPORT_DIR / "unmapped_rel_targets.csv"
SUMMARY_PATH = REPORT_DIR / "unmapped_rel_targets_summary.txt"


def parse_hex(value):
    text = str(value or "").strip()
    return int(text, 16) if text else None


def parse_decimal(value):
    text = str(value or "").strip()
    return int(text, 10) if text else None


def load_address_library(path):
    raw = path.read_bytes()
    if len(raw) < 8:
        raise RuntimeError("Address Library zu klein: {}".format(path))
    count = struct.unpack_from("<Q", raw, 0)[0]
    expected = 8 + count * 16
    if expected > len(raw):
        raise RuntimeError("Address Library ist abgeschnitten: {}".format(path))
    result = {}
    for index in range(count):
        rel_id, rva = struct.unpack_from("<QQ", raw, 8 + index * 16)
        result[int(rel_id)] = int(rva)
    return result


def load_csv_by_og_id(path):
    result = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row_number, row in enumerate(csv.DictReader(source, delimiter=";"), start=2):
            old_id = parse_decimal(row.get("OG_REL_ID"))
            if old_id is None:
                continue
            result[old_id] = {
                "csv_row": row_number,
                "csv_name": str(row.get("Name") or ""),
                "csv_og_rva": parse_hex(row.get("OG_Addr")),
                "csv_ae_rva": parse_hex(row.get("AE_221_Addr")),
                "csv_ae_id": parse_decimal(row.get("AE_221_REL_ID")),
            }
    return result


def main():
    address_library = load_address_library(OG_ADDRESS_LIBRARY)
    csv_by_id = load_csv_by_og_id(MAPPING_CSV)
    targets = []
    missing_library = 0
    rva_mismatches = 0
    with UNMAPPED_PATH.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            old_id = int(row["og_id"])
            rva = address_library.get(old_id)
            csv_row = csv_by_id.get(old_id, {})
            csv_rva = csv_row.get("csv_og_rva")
            if rva is None:
                missing_library += 1
            if rva is not None and csv_rva is not None and rva != csv_rva:
                rva_mismatches += 1
            targets.append(
                {
                    "og_id": old_id,
                    "kind": row["kinds"],
                    "og_rva": "" if rva is None else "0x{:X}".format(rva),
                    "csv_row": csv_row.get("csv_row", ""),
                    "csv_name": csv_row.get("csv_name", ""),
                    "csv_og_rva": "" if csv_rva is None else "0x{:X}".format(csv_rva),
                    "usage_count": row["usage_count"],
                    "locations": row["locations"],
                }
            )

    fields = [
        "og_id",
        "kind",
        "og_rva",
        "csv_row",
        "csv_name",
        "csv_og_rva",
        "usage_count",
        "locations",
    ]
    with OUTPUT_PATH.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows(targets)

    function_count = sum(1 for row in targets if row["kind"] == "function")
    data_count = sum(1 for row in targets if row["kind"] != "function")
    named_count = sum(1 for row in targets if row["csv_name"])
    summary = [
        "Current CommonLib unmapped REL targets",
        "Targets: {}".format(len(targets)),
        "Functions: {}".format(function_count),
        "Data/globals: {}".format(data_count),
        "Resolved by OG Address Library: {}".format(len(targets) - missing_library),
        "Missing from OG Address Library: {}".format(missing_library),
        "Targets with CSV names: {}".format(named_count),
        "CSV/Address-Library RVA mismatches: {}".format(rva_mismatches),
        "Output: {}".format(OUTPUT_PATH),
    ]
    SUMMARY_PATH.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
