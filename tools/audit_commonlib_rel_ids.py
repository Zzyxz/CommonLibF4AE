# SPDX-License-Identifier: MIT
"""Join CommonLibF4's direct REL::ID uses with the OG/AE semantic report."""

from __future__ import print_function

import csv
import os
import re
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
COMPARISON_PATH = REPORT_DIR / "rel_semantic_comparison.csv"
MEMBER_COMPARISON_PATH = REPORT_DIR / "member_offset_changes.csv"
AUDIT_PATH = REPORT_DIR / "current_commonlib_rel_id_audit.csv"
UNMAPPED_PATH = REPORT_DIR / "current_commonlib_unmapped_rel_ids.csv"
CURRENT_MEMBER_PATH = REPORT_DIR / "current_commonlib_member_offset_changes.csv"
SUMMARY_PATH = REPORT_DIR / "current_commonlib_rel_id_summary.txt"

SOURCE_ROOTS = ["CommonLibF4", "ExampleProject", "F4SEStub"]
GENERATED_HEADERS = {"RTTI_IDs.h", "VTABLE_IDs.h", "NiRTTI_IDs.h"}
ID_PATTERN = re.compile(r"REL::ID\s*\(\s*(\d+)\s*\)")


def load_comparisons(path):
    if not path.is_file():
        raise RuntimeError("Vergleichsbericht fehlt: {}".format(path))
    result = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            old_id = int(row["og_id"])
            result[old_id] = row
    return result


def source_files():
    for root_name in SOURCE_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in (".h", ".hpp", ".cpp", ".cxx"):
                if path.name not in GENERATED_HEADERS:
                    yield path


def find_uses():
    uses = []
    for path in source_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line_number, line in enumerate(source, start=1):
                for match in ID_PATTERN.finditer(line):
                    uses.append(
                        {
                            "og_id": int(match.group(1)),
                            "file": relative,
                            "line": line_number,
                            "kind": "function" if "func_t" in line else "data_or_global",
                            "source": line.strip(),
                        }
                    )
    return uses


def write_csv(path, fields, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    comparisons = load_comparisons(COMPARISON_PATH)
    uses = find_uses()
    audit = []
    by_id = defaultdict(list)
    for use in uses:
        by_id[use["og_id"]].append(use)
        comparison = comparisons.get(use["og_id"])
        row = dict(use)
        if comparison is None:
            row.update(
                {
                    "mapped": "no",
                    "ae_id": "",
                    "og_rva": "",
                    "ae_rva": "",
                    "csv_name": "",
                    "classification": "unmapped",
                    "score": "",
                }
            )
        else:
            row.update(
                {
                    "mapped": "yes",
                    "ae_id": comparison["ae_id"],
                    "og_rva": comparison["og_rva"],
                    "ae_rva": comparison["ae_rva"],
                    "csv_name": comparison["csv_name"],
                    "classification": comparison["classification"],
                    "score": comparison["score"],
                }
            )
        audit.append(row)

    fields = [
        "file",
        "line",
        "kind",
        "og_id",
        "mapped",
        "ae_id",
        "og_rva",
        "ae_rva",
        "csv_name",
        "classification",
        "score",
        "source",
    ]
    write_csv(AUDIT_PATH, fields, audit)

    unmapped = []
    for old_id, id_uses in sorted(by_id.items()):
        if old_id in comparisons:
            continue
        unmapped.append(
            {
                "og_id": old_id,
                "usage_count": len(id_uses),
                "kinds": ",".join(sorted({item["kind"] for item in id_uses})),
                "locations": " | ".join(
                    "{}:{}".format(item["file"], item["line"]) for item in id_uses
                ),
            }
        )
    write_csv(
        UNMAPPED_PATH,
        ["og_id", "usage_count", "kinds", "locations"],
        unmapped,
    )

    current_member_changes = []
    if MEMBER_COMPARISON_PATH.is_file():
        with MEMBER_COMPARISON_PATH.open("r", encoding="utf-8-sig", newline="") as source:
            for row in csv.DictReader(source, delimiter=";"):
                if int(row["og_id"]) in by_id:
                    current_member_changes.append(row)
    write_csv(
        CURRENT_MEMBER_PATH,
        [
            "csv_row",
            "csv_name",
            "og_id",
            "ae_id",
            "score",
            "common_offsets",
            "og_only_offsets",
            "ae_only_offsets",
        ],
        current_member_changes,
    )

    unique_counts = Counter()
    for old_id in by_id:
        comparison = comparisons.get(old_id)
        unique_counts[comparison["classification"] if comparison else "unmapped"] += 1
    mapped_unique = len(by_id) - unique_counts["unmapped"]
    summary = [
        "Current CommonLibF4 direct REL::ID audit",
        "Source occurrences: {}".format(len(uses)),
        "Unique OG IDs: {}".format(len(by_id)),
        "Directly mapped unique IDs: {}".format(mapped_unique),
        "Unmapped unique IDs: {}".format(unique_counts["unmapped"]),
        "Mapped exact semantics: {}".format(unique_counts["exact_semantics"]),
        "Mapped strong: {}".format(unique_counts["strong"]),
        "Mapped likely: {}".format(unique_counts["likely"]),
        "Mapped needs review: {}".format(unique_counts["review"]),
        "Mapped suspect: {}".format(unique_counts["suspect"]),
        "Mapped IDs with member-displacement changes: {}".format(len(current_member_changes)),
        "Audit: {}".format(AUDIT_PATH),
        "Unmapped: {}".format(UNMAPPED_PATH),
        "Member displacement review: {}".format(CURRENT_MEMBER_PATH),
    ]
    SUMMARY_PATH.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
