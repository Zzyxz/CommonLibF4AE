# SPDX-License-Identifier: MIT
"""Compare current relocation headers with an AE IDA/Address Library export."""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from pathlib import Path

from resolve_ae_address_library_ids import (
    DEFAULT_ADDRESS_LIBRARY,
    load_address_library,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CURRENT_DIR = REPO_ROOT / "CommonLibF4" / "include" / "RE"
GENERATED_DIR = Path(
    os.environ.get(
        "CLF4_AE_HEADER_EXPORT",
        str(REPO_ROOT / "build" / "ida-ae221-export"),
    )
)
REPORT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
ADDRESS_LIBRARY = Path(
    os.environ.get("CLF4_AE_ADDRESS_LIBRARY", str(DEFAULT_ADDRESS_LIBRARY))
)
HEADERS = ("RTTI_IDs.h", "VTABLE_IDs.h", "NiRTTI_IDs.h")

DECLARATION = re.compile(
    r"^\s*inline constexpr\s+(?P<type>.+?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\{\s*(?P<body>.*?)\s*\};\s*$"
)
ID_EXPRESSION = re.compile(r"REL::ID\((\d+)\)")
OFFSET_EXPRESSION = re.compile(r"REL::Offset\((0x[0-9A-Fa-f]+|\d+)\)")


@dataclass(frozen=True)
class RelocationValue:
    kind: str
    value: int

    def render(self) -> str:
        return str(self.value) if self.kind == "id" else f"offset:0x{self.value:X}"


def parse_header(path: Path) -> dict[str, list[RelocationValue]]:
    result: dict[str, list[RelocationValue]] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        match = DECLARATION.match(line)
        if not match:
            continue
        body = match.group("body")
        values: list[RelocationValue] = []
        for rel_id in ID_EXPRESSION.findall(body):
            values.append(RelocationValue("id", int(rel_id)))
        for offset in OFFSET_EXPRESSION.findall(body):
            values.append(RelocationValue("offset", int(offset, 0)))
        if not values and match.group("type") == "REL::ID" and body.isdecimal():
            values.append(RelocationValue("id", int(body)))
        if not values:
            raise RuntimeError(f"Cannot parse relocation at {path}:{line_number}")
        result[match.group("name")] = values
    return result


def resolve_rvas(
    values: list[RelocationValue], rva_by_id: dict[int, int]
) -> list[int | None]:
    return [
        rva_by_id.get(item.value) if item.kind == "id" else item.value
        for item in values
    ]


def render_values(values: list[RelocationValue] | None) -> str:
    return ",".join(item.render() for item in values or [])


def render_rvas(values: list[int | None] | None) -> str:
    return ",".join("" if item is None else f"0x{item:X}" for item in values or [])


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _ids_by_rva, rva_by_id, library_count = load_address_library(ADDRESS_LIBRARY)
    summary = [
        f"Address Library: {ADDRESS_LIBRARY}",
        f"Address Library entries: {library_count}",
    ]

    for header in HEADERS:
        current = parse_header(CURRENT_DIR / header)
        generated = parse_header(GENERATED_DIR / header)
        rows = []
        counts: dict[str, int] = {}

        for name in sorted(set(current) | set(generated)):
            current_values = current.get(name)
            generated_values = generated.get(name)
            current_rvas = (
                resolve_rvas(current_values, rva_by_id) if current_values else None
            )
            generated_rvas = (
                resolve_rvas(generated_values, rva_by_id) if generated_values else None
            )

            if current_values is None:
                status = "new_in_ae_export"
            elif generated_values is None:
                status = (
                    "name_missing_but_old_ids_resolve"
                    if all(item is not None for item in current_rvas or ())
                    else "name_missing_and_old_id_absent"
                )
            elif current_rvas == generated_rvas and all(
                item is not None for item in current_rvas or ()
            ):
                status = "current_ids_match_ae_rvas"
            elif all(item is not None for item in generated_rvas or ()):
                status = (
                    "replace_with_ae_offsets"
                    if any(item.kind == "offset" for item in generated_values)
                    else "replace_with_ae_ids"
                )
            else:
                status = "replace_with_ae_offsets"

            counts[status] = counts.get(status, 0) + 1
            rows.append(
                {
                    "name": name,
                    "status": status,
                    "current_values": render_values(current_values),
                    "current_ae_rvas": render_rvas(current_rvas),
                    "generated_values": render_values(generated_values),
                    "generated_ae_rvas": render_rvas(generated_rvas),
                }
            )

        report_path = REPORT_DIR / f"{Path(header).stem}_ae_migration.csv"
        with report_path.open("w", encoding="utf-8-sig", newline="") as target:
            writer = csv.DictWriter(
                target,
                fieldnames=list(rows[0]) if rows else [],
                delimiter=";",
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)

        summary.append(f"{header}: current={len(current)}, generated={len(generated)}")
        for status in sorted(counts):
            summary.append(f"  {status}: {counts[status]}")
        summary.append(f"  report: {report_path}")

    summary_path = REPORT_DIR / "generated_headers_ae_migration_summary.txt"
    summary.append(f"Summary: {summary_path}")
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
