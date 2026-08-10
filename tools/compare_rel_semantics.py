# SPDX-License-Identifier: MIT
"""Compare OG and AE semantic IDA exports produced by ida_export_rel_semantics.py."""

from __future__ import print_function

import csv
import json
import math
import os
import re
import sys
from collections import Counter
from difflib import SequenceMatcher
from itertools import zip_longest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


DEFAULT_INPUT_DIR = Path(
    os.environ.get(
        "CLF4_SEMANTIC_OUT",
        str(REPO_ROOT / "build" / "ida-semantic"),
    )
)
OG_PATH = DEFAULT_INPUT_DIR / "og_functions.jsonl"
AE_PATH = DEFAULT_INPUT_DIR / "ae221_functions.jsonl"
COMPARISON_PATH = DEFAULT_INPUT_DIR / "rel_semantic_comparison.csv"
SUSPECT_PATH = DEFAULT_INPUT_DIR / "suspect_matches.csv"
MEMBER_PATH = DEFAULT_INPUT_DIR / "member_offset_changes.csv"
SUMMARY_PATH = DEFAULT_INPUT_DIR / "comparison_summary.txt"


def clean_text(value):
    if value is None:
        return ""
    return str(value).replace("\0", "")


def iter_export(path):
    if not path.is_file():
        raise RuntimeError("Export fehlt: {}".format(path))
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("kind") == "metadata":
                continue
            yield record


def normalize_name(name):
    value = clean_text(name).lower()
    value = re.sub(r"^(?:j_|nullsub_|sub_)[0-9a-f]+$", "", value)
    value = re.sub(r"0x[0-9a-f]+|[0-9a-f]{7,}", "#", value)
    value = re.sub(r"\s+", "", value)
    return value


def name_similarity(left, right):
    left = normalize_name(left)
    right = normalize_name(right)
    if not left and not right:
        return 0.5
    if not left or not right:
        return 0.25
    return SequenceMatcher(None, left, right).ratio()


def closeness(left, right):
    left = abs(float(left or 0))
    right = abs(float(right or 0))
    if left == 0 and right == 0:
        return 1.0
    return min(left, right) / max(left, right)


def cosine(left, right):
    left = {clean_text(key): float(value) for key, value in (left or {}).items()}
    right = {clean_text(key): float(value) for key, value in (right or {}).items()}
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    common = set(left) & set(right)
    numerator = sum(left[key] * right[key] for key in common)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return numerator / (left_norm * right_norm)


def jaccard(left, right):
    left = set(left or [])
    right = set(right or [])
    if not left and not right:
        return 1.0
    return len(left & right) / float(len(left | right))


def pair_rows(references):
    result = set()
    for reference in references or []:
        for csv_row in reference.get("csv", []):
            if csv_row.get("og_id") is not None and csv_row.get("ae_id") is not None:
                result.add(int(csv_row["row"]))
    return result


def string_values(function):
    result = set()
    for item in function.get("strings", []):
        value = clean_text(item.get("text", "")).strip().lower()
        if value:
            result.add(value)
    return result


def offset_values(function):
    result = set()
    for value in (function.get("object_displacements") or {}):
        try:
            result.add(int(value))
        except ValueError:
            pass
    return result


def classification(score, exact_hash):
    if exact_hash:
        return "exact_semantics"
    if score >= 0.88:
        return "strong"
    if score >= 0.72:
        return "likely"
    if score >= 0.55:
        return "review"
    return "suspect"


def compare_record(og_record, ae_record):
    og = og_record.get("function", {})
    ae = ae_record.get("function", {})
    og_status = og.get("status", "missing")
    ae_status = ae.get("status", "missing")
    base = {
        "csv_row": og_record["row"],
        "csv_name": og_record.get("csv_name", ""),
        "og_id": og_record.get("og_id", ""),
        "ae_id": og_record.get("ae_id", ""),
        "og_rva": "0x{:X}".format(int(og_record["og_rva"])),
        "ae_rva": "0x{:X}".format(int(og_record["ae_rva"])),
        "og_status": og_status,
        "ae_status": ae_status,
        "og_name": og.get("demangled_name", og.get("raw_name", "")),
        "ae_name": ae.get("demangled_name", ae.get("raw_name", "")),
    }
    if og_status != "ok" or ae_status != "ok":
        base.update(
            {
                "classification": "unresolved",
                "score": "0.0000",
                "exact_semantic_hash": "no",
                "name_score": "0.0000",
                "size_score": "0.0000",
                "instruction_score": "0.0000",
                "cfg_score": "0.0000",
                "mnemonic_score": "0.0000",
                "shape_score": "0.0000",
                "calls_score": "0.0000",
                "callers_score": "0.0000",
                "strings_score": "0.0000",
                "member_offsets_score": "0.0000",
                "og_size": og.get("size", ""),
                "ae_size": ae.get("size", ""),
                "og_instructions": og.get("instruction_count", ""),
                "ae_instructions": ae.get("instruction_count", ""),
                "og_blocks": og.get("basic_block_count", ""),
                "ae_blocks": ae.get("basic_block_count", ""),
                "og_calls": len(og.get("calls", [])),
                "ae_calls": len(ae.get("calls", [])),
            }
        )
        return base, None

    scores = {
        "name": name_similarity(base["og_name"], base["ae_name"]),
        "size": closeness(og.get("size"), ae.get("size")),
        "instruction": closeness(og.get("instruction_count"), ae.get("instruction_count")),
        "cfg": (
            closeness(og.get("basic_block_count"), ae.get("basic_block_count"))
            + closeness(og.get("cfg_edge_count"), ae.get("cfg_edge_count"))
        )
        / 2.0,
        "mnemonic": cosine(og.get("mnemonics"), ae.get("mnemonics")),
        "shape": cosine(og.get("instruction_shapes"), ae.get("instruction_shapes")),
        "calls": jaccard(pair_rows(og.get("calls")), pair_rows(ae.get("calls"))),
        "callers": jaccard(pair_rows(og.get("callers")), pair_rows(ae.get("callers"))),
        "strings": jaccard(string_values(og), string_values(ae)),
        "member_offsets": jaccard(offset_values(og), offset_values(ae)),
    }
    score = (
        0.08 * scores["name"]
        + 0.08 * scores["size"]
        + 0.10 * scores["instruction"]
        + 0.10 * scores["cfg"]
        + 0.14 * scores["mnemonic"]
        + 0.18 * scores["shape"]
        + 0.14 * scores["calls"]
        + 0.07 * scores["callers"]
        + 0.06 * scores["strings"]
        + 0.05 * scores["member_offsets"]
    )
    exact_hash = bool(og.get("semantic_sha256")) and (
        og.get("semantic_sha256") == ae.get("semantic_sha256")
    )
    base.update(
        {
            "classification": classification(score, exact_hash),
            "score": "{:.4f}".format(score),
            "exact_semantic_hash": "yes" if exact_hash else "no",
            "name_score": "{:.4f}".format(scores["name"]),
            "size_score": "{:.4f}".format(scores["size"]),
            "instruction_score": "{:.4f}".format(scores["instruction"]),
            "cfg_score": "{:.4f}".format(scores["cfg"]),
            "mnemonic_score": "{:.4f}".format(scores["mnemonic"]),
            "shape_score": "{:.4f}".format(scores["shape"]),
            "calls_score": "{:.4f}".format(scores["calls"]),
            "callers_score": "{:.4f}".format(scores["callers"]),
            "strings_score": "{:.4f}".format(scores["strings"]),
            "member_offsets_score": "{:.4f}".format(scores["member_offsets"]),
            "og_size": og.get("size", 0),
            "ae_size": ae.get("size", 0),
            "og_instructions": og.get("instruction_count", 0),
            "ae_instructions": ae.get("instruction_count", 0),
            "og_blocks": og.get("basic_block_count", 0),
            "ae_blocks": ae.get("basic_block_count", 0),
            "og_calls": len(og.get("calls", [])),
            "ae_calls": len(ae.get("calls", [])),
        }
    )

    og_offsets = offset_values(og)
    ae_offsets = offset_values(ae)
    offset_change = None
    if (og_offsets or ae_offsets) and og_offsets != ae_offsets:
        offset_change = {
            "csv_row": og_record["row"],
            "csv_name": og_record.get("csv_name", ""),
            "og_id": og_record.get("og_id", ""),
            "ae_id": og_record.get("ae_id", ""),
            "score": "{:.4f}".format(score),
            "common_offsets": ",".join("0x{:X}".format(value) for value in sorted(og_offsets & ae_offsets)),
            "og_only_offsets": ",".join("0x{:X}".format(value) for value in sorted(og_offsets - ae_offsets)),
            "ae_only_offsets": ",".join("0x{:X}".format(value) for value in sorted(ae_offsets - og_offsets)),
        }
    return base, offset_change


def write_csv(path, fieldnames, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    DEFAULT_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    fields = [
        "csv_row",
        "csv_name",
        "og_id",
        "ae_id",
        "og_rva",
        "ae_rva",
        "og_status",
        "ae_status",
        "classification",
        "score",
        "exact_semantic_hash",
        "og_name",
        "ae_name",
        "name_score",
        "size_score",
        "instruction_score",
        "cfg_score",
        "mnemonic_score",
        "shape_score",
        "calls_score",
        "callers_score",
        "strings_score",
        "member_offsets_score",
        "og_size",
        "ae_size",
        "og_instructions",
        "ae_instructions",
        "og_blocks",
        "ae_blocks",
        "og_calls",
        "ae_calls",
    ]
    member_fields = [
        "csv_row",
        "csv_name",
        "og_id",
        "ae_id",
        "score",
        "common_offsets",
        "og_only_offsets",
        "ae_only_offsets",
    ]
    sentinel = object()
    compared_count = 0
    og_count = 0
    ae_count = 0
    offset_change_count = 0

    with COMPARISON_PATH.open("w", encoding="utf-8-sig", newline="") as comparison_file, \
        SUSPECT_PATH.open("w", encoding="utf-8-sig", newline="") as suspect_file, \
        MEMBER_PATH.open("w", encoding="utf-8-sig", newline="") as member_file:
        comparison_writer = csv.DictWriter(
            comparison_file, fieldnames=fields, delimiter=";", extrasaction="ignore"
        )
        suspect_writer = csv.DictWriter(
            suspect_file, fieldnames=fields, delimiter=";", extrasaction="ignore"
        )
        member_writer = csv.DictWriter(
            member_file, fieldnames=member_fields, delimiter=";", extrasaction="ignore"
        )
        comparison_writer.writeheader()
        suspect_writer.writeheader()
        member_writer.writeheader()

        for og_record, ae_record in zip_longest(
            iter_export(OG_PATH), iter_export(AE_PATH), fillvalue=sentinel
        ):
            if og_record is not sentinel:
                og_count += 1
            if ae_record is not sentinel:
                ae_count += 1
            if og_record is sentinel or ae_record is sentinel:
                counts["missing_export_side"] += 1
                continue
            if int(og_record["row"]) != int(ae_record["row"]):
                raise RuntimeError(
                    "Exportreihenfolge weicht ab: OG row {} / AE row {}".format(
                        og_record["row"], ae_record["row"]
                    )
                )

            comparison, offset_change = compare_record(og_record, ae_record)
            comparison_writer.writerow(comparison)
            compared_count += 1
            counts[comparison["classification"]] += 1
            if comparison["classification"] in ("suspect", "review", "unresolved"):
                suspect_writer.writerow(comparison)
            if offset_change is not None:
                member_writer.writerow(offset_change)
                offset_change_count += 1

    summary = [
        "CommonLibF4 OG 1.10.163 <-> AE 1.11.221 semantic comparison",
        "Format: CommonLibF4-semantic-v1",
        "OG records: {}".format(og_count),
        "AE records: {}".format(ae_count),
        "Compared rows: {}".format(compared_count),
        "Exact semantic hash: {}".format(counts["exact_semantics"]),
        "Strong matches: {}".format(counts["strong"]),
        "Likely matches: {}".format(counts["likely"]),
        "Needs review: {}".format(counts["review"]),
        "Suspect matches: {}".format(counts["suspect"]),
        "Unresolved functions: {}".format(counts["unresolved"]),
        "Missing export side: {}".format(counts["missing_export_side"]),
        "Rows with object/member displacement changes: {}".format(offset_change_count),
        "NOTE: Scores are triage evidence, not proof of ABI compatibility.",
        "Comparison: {}".format(COMPARISON_PATH),
        "Review queue: {}".format(SUSPECT_PATH),
        "Member offsets: {}".format(MEMBER_PATH),
    ]
    SUMMARY_PATH.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("FEHLER: {}".format(error), file=sys.stderr)
        sys.exit(1)
