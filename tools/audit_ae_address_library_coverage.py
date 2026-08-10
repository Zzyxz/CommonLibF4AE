# SPDX-License-Identifier: MIT
"""Audit every CommonLib REL::ID token against the Fallout 4 AE library."""

from __future__ import annotations

import csv
import os
import re
import struct
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "CommonLibF4"
ADDRESS_LIBRARY = Path(
    os.environ.get(
        "CLF4_AE_ADDRESS_LIBRARY",
        str(REPO_ROOT / "tools" / "inputs" / "version-1-11-221-0.bin"),
    )
)
OUTPUT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
ID_PATTERN = re.compile(r"REL::ID\(\s*(\d+)\s*\)")


def load_library(path: Path) -> dict[int, int]:
    raw = path.read_bytes()
    if len(raw) < 8:
        raise RuntimeError(f"Address Library is too small: {path}")
    count = struct.unpack_from("<Q", raw, 0)[0]
    expected_size = 8 + count * 16
    if len(raw) != expected_size:
        raise RuntimeError(
            f"Address Library size mismatch: expected {expected_size}, got {len(raw)}"
        )
    return {
        rel_id: rva
        for rel_id, rva in struct.iter_unpack("<QQ", raw[8:])
    }


def main() -> None:
    rva_by_id = load_library(ADDRESS_LIBRARY)
    occurrences: dict[int, list[str]] = defaultdict(list)
    for path in sorted(SOURCE_ROOT.rglob("*")):
        if path.suffix.lower() not in {".h", ".hpp", ".cpp", ".cxx"}:
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8-sig").splitlines(), start=1
        ):
            for match in ID_PATTERN.finditer(line):
                occurrences[int(match.group(1))].append(
                    f"{relative}:{line_number}"
                )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / "current_ae_address_library_coverage.csv"
    fields = ("rel_id", "rva", "status", "occurrence_count", "locations")
    with output.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields, delimiter=";")
        writer.writeheader()
        for rel_id, locations in sorted(occurrences.items()):
            rva = rva_by_id.get(rel_id)
            writer.writerow(
                {
                    "rel_id": rel_id,
                    "rva": f"0x{rva:X}" if rva is not None else "",
                    "status": "resolved" if rva is not None else "missing",
                    "occurrence_count": len(locations),
                    "locations": ",".join(locations),
                }
            )

    missing = sorted(set(occurrences) - set(rva_by_id))
    print(f"Address Library entries: {len(rva_by_id)}")
    print(f"REL::ID source occurrences: {sum(map(len, occurrences.values()))}")
    print(f"Unique source IDs: {len(occurrences)}")
    print(f"Resolved source IDs: {len(occurrences) - len(missing)}")
    print(f"Missing source IDs: {len(missing)}")
    print(f"Coverage CSV: {output}")
    if missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
