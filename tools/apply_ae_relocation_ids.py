# SPDX-License-Identifier: MIT
"""Apply reviewed AE Address Library IDs to direct CommonLib relocations."""

from __future__ import annotations

import argparse
import csv
import os
import re
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
) / "official_current_commonlib_ae_relocations.csv"
LOCATION = re.compile(r"(CommonLibF4/(?:include|src)/[^,:]+):(\d+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--tiers",
        default="high",
        help="Comma-separated confidence tiers to apply (default: high)",
    )
    parser.add_argument(
        "--include-existing-matches",
        action="store_true",
        help="Also apply rows whose pre-existing CSV AE ID matches the library",
    )
    parser.add_argument("--apply", action="store_true", help="Write source changes")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tiers = {item.strip() for item in args.tiers.split(",") if item.strip()}
    replacements_by_file: dict[Path, dict[int, int]] = defaultdict(dict)
    selected_rows = 0

    with args.report.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            selected_by_tier = row.get("confidence_tier") in tiers
            selected_by_existing = (
                args.include_existing_matches
                and row.get("existing_ae_id_status") == "match"
            )
            if not selected_by_tier and not selected_by_existing:
                continue
            if row.get("address_library_status") != "resolved_unique":
                continue
            if row.get("replacement_strategy", "id_only") != "id_only":
                continue
            old_id = int(row["og_id"])
            new_id = int(row["official_ae_id"])
            locations = LOCATION.findall(row.get("locations", ""))
            if not locations:
                raise RuntimeError(f"No source location for REL::ID({old_id})")
            selected_rows += 1
            for relative, _line in locations:
                path = REPO_ROOT / Path(relative)
                previous = replacements_by_file[path].setdefault(old_id, new_id)
                if previous != new_id:
                    raise RuntimeError(
                        f"Conflicting AE IDs for {old_id}: {previous} and {new_id}"
                    )

    changed_files = 0
    replaced_tokens = 0
    already_applied = 0
    for path, replacements in sorted(replacements_by_file.items()):
        original = path.read_text(encoding="utf-8")
        updated = original
        for old_id, new_id in sorted(replacements.items()):
            pattern = re.compile(rf"REL::ID\(\s*{old_id}\s*\)")
            updated, count = pattern.subn(f"REL::ID({new_id})", updated)
            if count == 0:
                new_pattern = re.compile(rf"REL::ID\(\s*{new_id}\s*\)")
                if new_pattern.search(updated):
                    already_applied += 1
                    continue
                raise RuntimeError(f"REL::ID({old_id}) not found in {path}")
            replaced_tokens += count
        if updated != original:
            changed_files += 1
            if args.apply:
                path.write_text(updated, encoding="utf-8", newline="")

    mode = "applied" if args.apply else "dry-run"
    print(f"Mode: {mode}")
    print(f"Confidence tiers: {','.join(sorted(tiers))}")
    print(f"Selected report rows: {selected_rows}")
    print(f"Files affected: {changed_files}")
    print(f"REL::ID tokens replaced: {replaced_tokens}")
    print(f"Mappings already applied: {already_applied}")


if __name__ == "__main__":
    main()
