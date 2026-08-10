# SPDX-License-Identifier: MIT
"""Consolidate all evidence into a conservative current-CommonLib AE map."""

from __future__ import print_function

import csv
import os
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
AUDIT_PATH = REPORT_DIR / "current_commonlib_rel_id_audit.csv"
TARGET_PATH = REPORT_DIR / "unmapped_rel_targets.csv"
FUNCTION_SEMANTIC_PATH = REPORT_DIR / "unmapped_function_best_candidates.csv"
FUNCTION_CONTEXT_PATH = REPORT_DIR / "unmapped_function_context_best_candidates.csv"
GLOBAL_CONTEXT_PATH = REPORT_DIR / "unmapped_global_context_best_candidates.csv"
OUTPUT_PATH = REPORT_DIR / "proposed_current_commonlib_ae_relocations.csv"
HIGH_PATH = REPORT_DIR / "high_confidence_current_commonlib_ae_relocations.csv"
SUMMARY_PATH = REPORT_DIR / "proposed_current_commonlib_ae_relocations_summary.txt"

SPECIAL = {
    1419793: {
        "ae_rva": "0x2438C30",
        "name": "__imp___std_type_info_name",
        "tier": "high",
        "evidence": "exact_ae_import_symbol",
    },
    161235: {
        "ae_rva": "0x3E5C6E0",
        "name": "__type_info_root_node candidate used by four __std_type_info_name callsites",
        "tier": "high",
        "evidence": "exact_typeinfo_callsite_argument",
    },
}


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source, delimiter=";"))


def index_by_id(path):
    return {int(row["og_id"]): row for row in read_csv(path)}


def source_locations():
    locations = defaultdict(set)
    kinds = defaultdict(set)
    for row in read_csv(AUDIT_PATH):
        old_id = int(row["og_id"])
        locations[old_id].add("{}:{}".format(row["file"], row["line"]))
        kinds[old_id].add(row["kind"])
    return locations, kinds


def choose_function(old_id, semantic, context):
    context_class = context.get("confidence", "")
    semantic_class = semantic.get("confidence", "")
    context_rva = context.get("ae_rva", "")
    semantic_rva = semantic.get("ae_rva", "")
    agrees = bool(context_rva and semantic_rva and context_rva == semantic_rva)
    exact_calls = int(context.get("exact_pair_calls") or 0)
    unique_rows = int(context.get("unique_pair_rows") or 0)

    if context_class in ("confirmed_agreement", "strong_agreement") and agrees:
        return context_rva, "high", "semantic_and_call_context_agree", context
    if context_class == "strong_exact_context" and exact_calls >= 1:
        return context_rva, "high", "exact_paired_callsite_context", context
    if context_class == "strong_context" and unique_rows >= 3:
        tier = "high" if agrees else "medium"
        evidence = "strong_call_context_agrees" if agrees else "strong_call_context_conflicts_semantic"
        return context_rva, tier, evidence, context
    if context_class in ("likely_context", "likely_agreement"):
        tier = "medium" if agrees else "review"
        evidence = "likely_call_context_agrees" if agrees else "likely_call_context_only"
        return context_rva, tier, evidence, context
    if context_class == "review" and agrees:
        return context_rva, "medium", "weak_call_context_agrees_with_semantic", context

    if semantic_rva:
        if semantic_class == "exact_unique":
            return semantic_rva, "high", "unique_exact_normalized_semantics", semantic
        if semantic_class == "strong_unique":
            return semantic_rva, "medium", "unique_strong_semantic_candidate", semantic
        if semantic_class == "likely_unique":
            return semantic_rva, "review", "unique_likely_semantic_candidate", semantic
        return semantic_rva, "review", "best_semantic_candidate_only", semantic
    if context_rva:
        return context_rva, "review", "best_call_context_candidate_only", context
    return "", "unresolved", "no_function_candidate", {}


def choose_global(row):
    confidence = row.get("confidence", "")
    rva = row.get("ae_rva", "")
    if confidence in ("strong_name", "strong_exact_context"):
        return rva, "high", confidence
    if confidence == "strong_context":
        return rva, "high", "strong_instruction_context"
    if confidence == "likely_context":
        return rva, "medium", "likely_instruction_context"
    if confidence == "review" and rva:
        return rva, "review", "ambiguous_instruction_context"
    return "", "unresolved", "no_paired_xref_candidate"


def main():
    locations, kinds = source_locations()
    audit = read_csv(AUDIT_PATH)
    targets = index_by_id(TARGET_PATH)
    semantic = index_by_id(FUNCTION_SEMANTIC_PATH)
    function_context = index_by_id(FUNCTION_CONTEXT_PATH)
    global_context = index_by_id(GLOBAL_CONTEXT_PATH)

    direct = {}
    for row in audit:
        old_id = int(row["og_id"])
        if row["mapped"] == "yes":
            direct[old_id] = row

    all_ids = sorted(set(locations))
    rows = []
    for old_id in all_ids:
        location_text = " | ".join(sorted(locations[old_id]))
        kind_text = ",".join(sorted(kinds[old_id]))
        result = {
            "og_id": old_id,
            "kind": kind_text,
            "og_rva": "",
            "ae_rva": "",
            "existing_ae_id": "",
            "confidence_tier": "unresolved",
            "evidence": "",
            "symbol_name": "",
            "primary_score": "",
            "locations": location_text,
            "manual_review": "yes",
        }

        if old_id in direct:
            source = direct[old_id]
            classification = source["classification"]
            tier = "high" if classification in ("exact_semantics", "strong") else "medium"
            result.update(
                {
                    "og_rva": source["og_rva"],
                    "ae_rva": source["ae_rva"],
                    "existing_ae_id": source["ae_id"],
                    "confidence_tier": tier,
                    "evidence": "confirmed_csv_pair_{}".format(classification),
                    "symbol_name": source["csv_name"],
                    "primary_score": source["score"],
                    "manual_review": "no" if tier == "high" else "yes",
                }
            )
        else:
            target = targets.get(old_id, {})
            result["og_rva"] = target.get("og_rva", "")
            if old_id in SPECIAL:
                special = SPECIAL[old_id]
                result.update(
                    {
                        "ae_rva": special["ae_rva"],
                        "confidence_tier": special["tier"],
                        "evidence": special["evidence"],
                        "symbol_name": special["name"],
                        "manual_review": "no",
                    }
                )
            elif target.get("kind") == "function":
                ae_rva, tier, evidence, source = choose_function(
                    old_id, semantic.get(old_id, {}), function_context.get(old_id, {})
                )
                result.update(
                    {
                        "ae_rva": ae_rva,
                        "existing_ae_id": source.get("existing_ae_ids", ""),
                        "confidence_tier": tier,
                        "evidence": evidence,
                        "symbol_name": target.get("csv_name") or source.get("target_name", ""),
                        "primary_score": source.get("score")
                        or source.get("vote_score", ""),
                        "manual_review": "no" if tier == "high" else "yes",
                    }
                )
            else:
                source = global_context.get(old_id, {})
                ae_rva, tier, evidence = choose_global(source)
                result.update(
                    {
                        "ae_rva": ae_rva,
                        "confidence_tier": tier,
                        "evidence": evidence,
                        "symbol_name": source.get("og_name", ""),
                        "primary_score": source.get("vote_score", ""),
                        "manual_review": "no" if tier == "high" else "yes",
                    }
                )
        rows.append(result)

    high_by_rva = defaultdict(list)
    for row in rows:
        if row["confidence_tier"] == "high" and row["ae_rva"]:
            high_by_rva[row["ae_rva"]].append(row["og_id"])
    for row in rows:
        conflicting_ids = [
            old_id for old_id in high_by_rva.get(row["ae_rva"], []) if old_id != row["og_id"]
        ]
        if conflicting_ids and row["confidence_tier"] in ("medium", "review"):
            row["confidence_tier"] = "review"
            row["manual_review"] = "yes"
            row["evidence"] += "_rva_conflicts_with_high_id_{}".format(
                ",".join(str(old_id) for old_id in conflicting_ids)
            )

    fields = [
        "og_id",
        "kind",
        "og_rva",
        "ae_rva",
        "existing_ae_id",
        "confidence_tier",
        "evidence",
        "symbol_name",
        "primary_score",
        "locations",
        "manual_review",
    ]
    high_rows = [row for row in rows if row["confidence_tier"] == "high"]
    for path, selected in ((OUTPUT_PATH, rows), (HIGH_PATH, high_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(selected)

    counts = Counter(row["confidence_tier"] for row in rows)
    with_candidate = sum(1 for row in rows if row["ae_rva"])
    summary = [
        "Current CommonLibF4 AE 1.11.221 relocation consolidation",
        "Unique source IDs: {}".format(len(rows)),
        "IDs with an AE RVA candidate: {}".format(with_candidate),
        "High confidence: {}".format(counts["high"]),
        "Medium confidence: {}".format(counts["medium"]),
        "Review candidate: {}".format(counts["review"]),
        "Unresolved: {}".format(counts["unresolved"]),
        "NOTE: No runtime Address Library was generated from incomplete/review evidence.",
        "All candidates: {}".format(OUTPUT_PATH),
        "High confidence only: {}".format(HIGH_PATH),
    ]
    SUMMARY_PATH.write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
