# SPDX-License-Identifier: MIT
"""Resolve proposed Fallout 4 AE RVAs to official Address Library IDs.

The input report is produced by ``consolidate_ae_relocation_candidates.py``.
This script does not modify CommonLib sources or the Address Library.  It emits
an augmented CSV and a short coverage summary for review.
"""

from __future__ import annotations

import csv
import os
import struct
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ADDRESS_LIBRARY = Path(
    REPO_ROOT / "tools" / "inputs" / "version-1-11-221-0.bin"
)
DEFAULT_REPORT_DIR = REPO_ROOT / "build" / "ida-semantic"
DEFAULT_OVERRIDES = REPO_ROOT / "tools" / "ae_relocation_overrides.csv"

ADDRESS_LIBRARY = Path(
    os.environ.get("CLF4_AE_ADDRESS_LIBRARY", str(DEFAULT_ADDRESS_LIBRARY))
)
REPORT_DIR = Path(os.environ.get("CLF4_SEMANTIC_OUT", str(DEFAULT_REPORT_DIR)))
INPUT_CSV = REPORT_DIR / "proposed_current_commonlib_ae_relocations.csv"
OUTPUT_CSV = REPORT_DIR / "official_current_commonlib_ae_relocations.csv"
SUMMARY = REPORT_DIR / "official_current_commonlib_ae_relocations_summary.txt"
OVERRIDES = Path(
    os.environ.get("CLF4_AE_RELOCATION_OVERRIDES", str(DEFAULT_OVERRIDES))
)


def parse_integer(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    return int(text, 0)


def load_address_library(
    path: Path,
) -> tuple[dict[int, list[int]], dict[int, int], int]:
    raw = path.read_bytes()
    if len(raw) < 8:
        raise RuntimeError(f"Address Library is too small: {path}")

    count = struct.unpack_from("<Q", raw, 0)[0]
    expected_size = 8 + count * 16
    if len(raw) != expected_size:
        raise RuntimeError(
            f"Address Library size mismatch: expected {expected_size}, got {len(raw)}"
        )

    ids_by_rva: dict[int, list[int]] = defaultdict(list)
    rva_by_id: dict[int, int] = {}
    for index in range(count):
        rel_id, rva = struct.unpack_from("<QQ", raw, 8 + index * 16)
        ids_by_rva[rva].append(rel_id)
        rva_by_id[rel_id] = rva
    return dict(ids_by_rva), rva_by_id, count


def load_overrides(path: Path) -> dict[int, dict[str, str]]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source, delimiter=";"))
    result = {}
    for row in rows:
        old_id = parse_integer(row.get("og_id"))
        if old_id is None:
            raise RuntimeError(f"Override without og_id in {path}")
        if old_id in result:
            raise RuntimeError(f"Duplicate override for {old_id} in {path}")
        result[old_id] = row
    return result


def main() -> None:
    if not ADDRESS_LIBRARY.is_file():
        raise FileNotFoundError(f"Address Library not found: {ADDRESS_LIBRARY}")
    if not INPUT_CSV.is_file():
        raise FileNotFoundError(f"Candidate report not found: {INPUT_CSV}")

    ids_by_rva, rva_by_id, library_count = load_address_library(ADDRESS_LIBRARY)
    overrides = load_overrides(OVERRIDES)
    with INPUT_CSV.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, delimiter=";")
        rows = list(reader)
        source_fields = list(reader.fieldnames or ())

    resolved = 0
    unique = 0
    missing_rva = 0
    unresolved_candidate = 0
    existing_matches = 0
    existing_conflicts = 0
    old_ids_present = 0
    old_ids_match_candidate = 0
    resolved_by_tier: dict[str, int] = defaultdict(int)
    overrides_used = 0

    output_rows: list[dict[str, str]] = []
    for source_row in rows:
        row = dict(source_row)
        old_id = parse_integer(row.get("og_id"))
        original_ae_rva = parse_integer(row.get("ae_rva"))
        override = overrides.get(old_id) if old_id is not None else None
        if override:
            override_rva = parse_integer(override.get("ae_rva"))
            if override_rva is None:
                raise RuntimeError(f"Override for {old_id} has no AE RVA")
            allows_correction = override.get("allow_candidate_correction", "").lower() == "yes"
            if (
                original_ae_rva is not None
                and original_ae_rva != override_rva
                and not allows_correction
            ):
                raise RuntimeError(
                    f"Override for {old_id} conflicts with proposed AE RVA"
                )
            ae_rva = override_rva
            row["ae_rva"] = f"0x{ae_rva:X}"
            row["confidence_tier"] = override.get("confidence_tier", "high")
            row["evidence"] = override.get("evidence", "targeted_override")
            row["manual_review"] = "no"
            resolution_source = "targeted_override"
            replacement_strategy = override.get("replacement_strategy", "id_only")
            overrides_used += 1
        else:
            ae_rva = original_ae_rva
            resolution_source = "proposed_report"
            replacement_strategy = "id_only"
        official_ids = ids_by_rva.get(ae_rva, []) if ae_rva is not None else []
        existing_id = parse_integer(row.get("existing_ae_id"))
        old_id_rva = rva_by_id.get(old_id) if old_id is not None else None

        if ae_rva is None:
            status = "unresolved_candidate"
            unresolved_candidate += 1
        elif not official_ids:
            status = "rva_missing_from_address_library"
            missing_rva += 1
        elif len(official_ids) == 1:
            status = "resolved_unique"
            resolved += 1
            unique += 1
        else:
            status = "resolved_aliases"
            resolved += 1

        if official_ids:
            resolved_by_tier[row.get("confidence_tier", "unknown")] += 1

        if existing_id is None or not official_ids:
            existing_status = "not_comparable"
        elif existing_id in official_ids:
            existing_status = "match"
            existing_matches += 1
        else:
            existing_status = "conflict"
            existing_conflicts += 1

        if old_id_rva is not None:
            old_ids_present += 1
            if old_id_rva == ae_rva:
                old_ids_match_candidate += 1

        row["official_ae_id"] = str(official_ids[0]) if official_ids else ""
        row["official_ae_ids"] = ",".join(str(item) for item in official_ids)
        row["address_library_status"] = status
        row["existing_ae_id_status"] = existing_status
        row["old_id_ae_rva"] = f"0x{old_id_rva:X}" if old_id_rva is not None else ""
        row["old_id_matches_candidate"] = (
            "yes" if old_id_rva is not None and old_id_rva == ae_rva else "no"
        )
        row["original_ae_rva"] = (
            f"0x{original_ae_rva:X}" if original_ae_rva is not None else ""
        )
        row["resolution_source"] = resolution_source
        row["replacement_strategy"] = replacement_strategy
        output_rows.append(row)

    output_fields = source_fields + [
        "official_ae_id",
        "official_ae_ids",
        "address_library_status",
        "existing_ae_id_status",
        "old_id_ae_rva",
        "old_id_matches_candidate",
        "original_ae_rva",
        "resolution_source",
        "replacement_strategy",
    ]
    with OUTPUT_CSV.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(
            target, fieldnames=output_fields, delimiter=";", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(output_rows)

    summary_lines = [
        f"Address Library: {ADDRESS_LIBRARY}",
        f"Address Library entries: {library_count}",
        f"Address Library unique RVAs: {len(ids_by_rva)}",
        f"Candidate rows: {len(rows)}",
        f"Resolved by exact AE RVA: {resolved}",
        f"Resolved to one ID: {unique}",
        f"Candidate RVA missing from Address Library: {missing_rva}",
        f"Candidate has no AE RVA: {unresolved_candidate}",
        f"Existing AE ID matches official ID: {existing_matches}",
        f"Existing AE ID conflicts with official ID: {existing_conflicts}",
        f"Old numeric IDs present in AE library: {old_ids_present}",
        f"Old numeric IDs map to candidate AE RVA: {old_ids_match_candidate}",
        f"Targeted overrides used: {overrides_used}",
        f"Targeted overrides file: {OVERRIDES}",
        "Resolved by confidence tier:",
    ]
    for tier in sorted(resolved_by_tier):
        summary_lines.append(f"  {tier}: {resolved_by_tier[tier]}")
    summary_lines.extend([f"CSV: {OUTPUT_CSV}", f"Summary: {SUMMARY}"])
    SUMMARY.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print("\n".join(summary_lines))


if __name__ == "__main__":
    main()
