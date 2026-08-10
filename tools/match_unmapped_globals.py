# SPDX-License-Identifier: MIT
"""Vote for AE global/data RVAs using confirmed OG/AE function-pair xrefs."""

from __future__ import print_function

import csv
import json
import os
import re
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from itertools import zip_longest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
TARGET_PATH = REPORT_DIR / "unmapped_rel_targets.csv"
OG_EXPORT = REPORT_DIR / "og_functions.jsonl"
AE_EXPORT = REPORT_DIR / "ae221_functions.jsonl"
CANDIDATE_PATH = REPORT_DIR / "unmapped_global_candidates.csv"
BEST_PATH = REPORT_DIR / "unmapped_global_best_candidates.csv"
SUMMARY_PATH = REPORT_DIR / "unmapped_global_match_summary.txt"
TOP_CANDIDATES = 10


def parse_hex(value):
    text = str(value or "").strip()
    return int(text, 16) if text else None


def load_targets(path):
    targets = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            if row["kind"] == "function":
                continue
            rva = parse_hex(row["og_rva"])
            targets[rva] = {
                "og_id": int(row["og_id"]),
                "og_rva": rva,
                "locations": row["locations"],
            }
    return targets


def iter_export(path):
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            if record.get("kind") != "metadata":
                yield record


def generic_name(name):
    value = str(name or "")
    return not value or bool(
        re.match(r"^(?:qword|dword|word|byte|unk|off|stru|asc|loc|sub)_[0-9A-Fa-f]+$", value)
    )


def normalize_name(name):
    value = str(name or "").lower()
    value = re.sub(r"^(?:qword|dword|word|byte|unk|off|stru|asc|loc|sub)_[0-9a-f]+$", "", value)
    value = re.sub(r"[0-9a-f]{7,}", "#", value)
    return re.sub(r"[^a-z0-9_]+", "", value)


def name_score(left, right):
    left = normalize_name(left)
    right = normalize_name(right)
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def segment_class(name):
    value = str(name or "").lower()
    if "text" in value:
        return "code"
    if "idata" in value or "extern" in value:
        return "import"
    if "rdata" in value or "const" in value:
        return "readonly"
    if "data" in value or "bss" in value:
        return "data"
    return value


def confidence(row, second):
    anchors = int(row["anchor_count"])
    unique_anchors = int(row["unique_anchor_count"])
    score = float(row["vote_score"])
    second_score = float(second["vote_score"]) if second else 0.0
    margin = score - second_score
    ratio = score / second_score if second_score > 0 else (999.0 if score > 0 else 0.0)
    if float(row["name_score"]) >= 0.85 and unique_anchors >= 1 and margin > 0:
        return "strong_name", margin, ratio
    if unique_anchors >= 3 and ratio >= 1.5 and margin >= 0.5:
        return "strong_xrefs", margin, ratio
    if unique_anchors >= 2 and ratio >= 1.8 and margin >= 0.5:
        return "likely_xrefs", margin, ratio
    if anchors == 1 and int(row["single_candidate_anchors"]) == 1:
        return "single_xref_unique", margin, ratio
    if score > 0:
        return "review", margin, ratio
    return "unresolved", margin, ratio


def main():
    targets = load_targets(TARGET_PATH)
    evidence = {
        rva: {
            "target": target,
            "og_names": Counter(),
            "og_segments": Counter(),
            "anchors": set(),
            "candidate_scores": Counter(),
            "candidate_anchors": defaultdict(set),
            "candidate_single_anchors": Counter(),
            "candidate_descriptors": {},
        }
        for rva, target in targets.items()
    }
    sentinel = object()
    pair_count = 0

    for og_record, ae_record in zip_longest(
        iter_export(OG_EXPORT), iter_export(AE_EXPORT), fillvalue=sentinel
    ):
        if og_record is sentinel or ae_record is sentinel:
            raise RuntimeError("OG/AE-Exportlaengen stimmen nicht ueberein")
        if int(og_record["row"]) != int(ae_record["row"]):
            raise RuntimeError("OG/AE-Exportreihenfolge stimmt nicht ueberein")
        pair_count += 1
        og_function = og_record.get("function", {})
        ae_function = ae_record.get("function", {})
        if og_function.get("status") != "ok" or ae_function.get("status") != "ok":
            continue

        og_refs = {int(item["rva"]): item for item in og_function.get("data_refs", [])}
        hit_rvas = set(og_refs) & set(targets)
        if not hit_rvas:
            continue
        ae_refs = ae_function.get("data_refs", [])
        anchor_row = int(og_record["row"])

        for target_rva in hit_rvas:
            item = evidence[target_rva]
            og_ref = og_refs[target_rva]
            item["og_names"][str(og_ref.get("name", ""))] += 1
            item["og_segments"][str(og_ref.get("segment", ""))] += 1
            item["anchors"].add(anchor_row)
            og_segment_class = segment_class(og_ref.get("segment", ""))
            candidate_count = max(1, len(ae_refs))

            for ae_ref in ae_refs:
                candidate_rva = int(ae_ref["rva"])
                candidate_segment_class = segment_class(ae_ref.get("segment", ""))
                if og_segment_class and candidate_segment_class != og_segment_class:
                    continue
                segment_bonus = 0.35
                candidate_name_score = name_score(og_ref.get("name", ""), ae_ref.get("name", ""))
                weight = (1.0 / candidate_count) + segment_bonus + (2.0 * candidate_name_score)
                item["candidate_scores"][candidate_rva] += weight
                item["candidate_anchors"][candidate_rva].add(anchor_row)
                if len(ae_refs) == 1:
                    item["candidate_single_anchors"][candidate_rva] += 1
                item["candidate_descriptors"][candidate_rva] = ae_ref

    all_rows = []
    best_rows = []
    counts = Counter()
    for target_rva, item in sorted(evidence.items()):
        target = item["target"]
        og_name = item["og_names"].most_common(1)[0][0] if item["og_names"] else ""
        og_segment = item["og_segments"].most_common(1)[0][0] if item["og_segments"] else ""
        ranked = []
        for candidate_rva, score in item["candidate_scores"].items():
            descriptor = item["candidate_descriptors"][candidate_rva]
            ranked.append(
                {
                    "og_id": target["og_id"],
                    "og_rva": "0x{:X}".format(target_rva),
                    "og_name": og_name,
                    "og_segment": og_segment,
                    "locations": target["locations"],
                    "anchor_count": len(item["anchors"]),
                    "unique_anchor_count": len(item["candidate_anchors"][candidate_rva]),
                    "single_candidate_anchors": item["candidate_single_anchors"][candidate_rva],
                    "vote_score": "{:.6f}".format(score),
                    "name_score": "{:.4f}".format(name_score(og_name, descriptor.get("name", ""))),
                    "ae_rva": "0x{:X}".format(candidate_rva),
                    "ae_name": descriptor.get("name", ""),
                    "ae_segment": descriptor.get("segment", ""),
                }
            )
        ranked.sort(
            key=lambda row: (
                float(row["vote_score"]),
                int(row["unique_anchor_count"]),
                float(row["name_score"]),
            ),
            reverse=True,
        )
        ranked = ranked[:TOP_CANDIDATES]
        best = ranked[0] if ranked else None
        second = ranked[1] if len(ranked) > 1 else None
        result_confidence, margin, ratio = (
            confidence(best, second) if best else ("unresolved", 0.0, 0.0)
        )
        counts[result_confidence] += 1

        if not ranked:
            best_rows.append(
                {
                    "og_id": target["og_id"],
                    "og_rva": "0x{:X}".format(target_rva),
                    "locations": target["locations"],
                    "confidence": "unresolved",
                    "rank": "",
                    "anchor_count": 0,
                }
            )
            continue
        for rank, row in enumerate(ranked, start=1):
            row["rank"] = rank
            row["confidence"] = result_confidence if rank == 1 else "alternative"
            row["margin_to_second"] = "{:.6f}".format(margin) if rank == 1 else ""
            row["ratio_to_second"] = "{:.4f}".format(ratio) if rank == 1 else ""
            all_rows.append(row)
            if rank == 1:
                best_rows.append(row)

    fields = [
        "og_id",
        "og_rva",
        "og_name",
        "og_segment",
        "locations",
        "rank",
        "confidence",
        "anchor_count",
        "unique_anchor_count",
        "single_candidate_anchors",
        "vote_score",
        "margin_to_second",
        "ratio_to_second",
        "name_score",
        "ae_rva",
        "ae_name",
        "ae_segment",
    ]
    for path, rows in ((CANDIDATE_PATH, all_rows), (BEST_PATH, best_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    summary = [
        "CommonLibF4 unmapped global/data matching",
        "Confirmed function pairs scanned: {}".format(pair_count),
        "Targets: {}".format(len(targets)),
        "Strong by name: {}".format(counts["strong_name"]),
        "Strong by xrefs: {}".format(counts["strong_xrefs"]),
        "Likely by xrefs: {}".format(counts["likely_xrefs"]),
        "Single unique xref: {}".format(counts["single_xref_unique"]),
        "Needs review: {}".format(counts["review"]),
        "Unresolved: {}".format(counts["unresolved"]),
        "Best candidates: {}".format(BEST_PATH),
        "All candidates: {}".format(CANDIDATE_PATH),
    ]
    SUMMARY_PATH.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
