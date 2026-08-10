# SPDX-License-Identifier: MIT
"""Find AE candidates for CommonLib's currently unmapped OG function IDs.

Run this read-only IDA script first with CLF4_IDA_SIDE=og to export the 73 OG
target profiles.  Run it again with CLF4_IDA_SIDE=ae221 to score every AE IDA
function against those profiles.  Confirmed CSV function pairs are used as
cross-version callgraph anchors.
"""

from __future__ import print_function

import csv
import heapq
import json
import os
import sys
import time
import traceback
from collections import Counter
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import compare_rel_semantics as comparison_tools
import ida_export_rel_semantics as semantic_tools


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
TARGET_PATH = OUTPUT_DIR / "unmapped_rel_targets.csv"
OG_PROFILE_PATH = OUTPUT_DIR / "unmapped_og_function_profiles.jsonl"
CANDIDATE_PATH = OUTPUT_DIR / "unmapped_function_candidates.csv"
BEST_PATH = OUTPUT_DIR / "unmapped_function_best_candidates.csv"
SUMMARY_PATH = OUTPUT_DIR / "unmapped_function_match_summary.txt"
OG_SUMMARY_PATH = OUTPUT_DIR / "unmapped_og_function_profile_summary.txt"
TOP_CANDIDATES = 10
PROGRESS_INTERVAL = 5000


try:
    import idaapi
    import ida_funcs
    import ida_kernwin
    import ida_nalt
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_kernwin = None
    ida_nalt = None
    idautils = None
    idc = None


def parse_hex(value):
    text = str(value or "").strip()
    return int(text, 16) if text else None


def load_targets(path):
    targets = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            if row["kind"] != "function":
                continue
            targets.append(
                {
                    "og_id": int(row["og_id"]),
                    "og_rva": parse_hex(row["og_rva"]),
                    "csv_name": row["csv_name"],
                    "locations": row["locations"],
                }
            )
    return targets


def load_og_profiles(path):
    profiles = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("kind") == "metadata":
                continue
            if record.get("function", {}).get("status") == "ok":
                profiles.append(record)
    return profiles


def write_og_profiles(targets, imagebase, exporter):
    counts = Counter()
    with OG_PROFILE_PATH.open("w", encoding="utf-8", newline="\n") as output:
        output.write(
            json.dumps(
                {
                    "kind": "metadata",
                    "format": "CommonLibF4-unmapped-functions-v1",
                    "side": "og",
                    "target_count": len(targets),
                    "imagebase": imagebase,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        for target in targets:
            record = dict(target)
            record["kind"] = "function_target"
            try:
                record["function"] = exporter.extract_function(imagebase + target["og_rva"])
                counts[record["function"].get("status", "unknown")] += 1
            except Exception:
                counts["error"] += 1
                record["function"] = {
                    "status": "error",
                    "message": traceback.format_exc().splitlines()[-1],
                }
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return counts


def profile_record(profile, ae_rva=None, ae_function=None):
    return {
        "row": profile["og_id"],
        "csv_name": profile.get("csv_name", ""),
        "og_id": profile["og_id"],
        "ae_id": "",
        "og_rva": profile["og_rva"],
        "ae_rva": 0 if ae_rva is None else ae_rva,
        "function": profile["function"] if ae_function is None else ae_function,
    }


def candidate_csv_rows(index, rva):
    return [
        row
        for row in index.rows_for_rva(rva)
        if row.get("og_id") is not None and row.get("ae_id") is not None
    ]


def eligible(profile, candidate):
    old = profile["function"]
    if old.get("semantic_sha256") == candidate.get("semantic_sha256"):
        return True
    instruction_score = comparison_tools.closeness(
        old.get("instruction_count"), candidate.get("instruction_count")
    )
    size_score = comparison_tools.closeness(old.get("size"), candidate.get("size"))
    if instruction_score < 0.25 or size_score < 0.20:
        name_score = comparison_tools.name_similarity(
            old.get("demangled_name", old.get("raw_name", "")),
            candidate.get("demangled_name", candidate.get("raw_name", "")),
        )
        return name_score >= 0.72
    mnemonic_score = comparison_tools.cosine(
        old.get("mnemonics"), candidate.get("mnemonics")
    )
    return mnemonic_score >= 0.45


def score_candidate(profile, candidate, candidate_rva, csv_rows):
    old_record = profile_record(profile, ae_rva=candidate_rva)
    ae_record = profile_record(profile, ae_rva=candidate_rva, ae_function=candidate)
    result, _unused = comparison_tools.compare_record(old_record, ae_record)
    score = float(result["score"])
    exact_hash = result["exact_semantic_hash"] == "yes"
    mapped_to_other = bool(csv_rows)
    # A function may legitimately merge with an existing mapped function, so
    # this is a small ranking penalty and never a hard exclusion.
    ranking_score = score - (0.025 if mapped_to_other else 0.0)
    return ranking_score, score, exact_hash, result


def confidence(best, second):
    score = float(best["score"])
    ranking_score = float(best.get("ranking_score", score))
    second_ranking_score = (
        float(second.get("ranking_score", second["score"])) if second else 0.0
    )
    margin = ranking_score - second_ranking_score
    exact_hash = best.get("exact_hash") is True or str(best.get("exact_hash", "")).lower() == "yes"
    if exact_hash and margin >= 0.03:
        return "exact_unique", margin
    if score >= 0.88 and margin >= 0.06:
        return "strong_unique", margin
    if score >= 0.80 and margin >= 0.08:
        return "likely_unique", margin
    return "review", margin


def candidate_fields():
    return [
        "og_id",
        "og_rva",
        "target_name",
        "locations",
        "rank",
        "confidence",
        "score",
        "ranking_score",
        "margin_to_second",
        "exact_hash",
        "ae_rva",
        "ae_name",
        "existing_ae_ids",
        "existing_pair_rows",
        "mapped_to_other",
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
    ]


def write_candidates(profiles, heaps):
    all_rows = []
    best_rows = []
    counts = Counter()
    for profile in profiles:
        candidates = [item[2] for item in sorted(heaps[profile["og_id"]], reverse=True)]
        best = candidates[0] if candidates else None
        second = candidates[1] if len(candidates) > 1 else None
        result_confidence, margin = confidence(best, second) if best else ("unresolved", 0.0)
        counts[result_confidence] += 1
        for rank, candidate in enumerate(candidates, start=1):
            row = dict(candidate)
            row.update(
                {
                    "rank": rank,
                    "confidence": result_confidence if rank == 1 else "alternative",
                    "margin_to_second": "{:.4f}".format(margin) if rank == 1 else "",
                }
            )
            all_rows.append(row)
            if rank == 1:
                best_rows.append(row)

    fields = candidate_fields()
    for path, rows in ((CANDIDATE_PATH, all_rows), (BEST_PATH, best_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    return counts, best_rows


def rerank_existing_candidates():
    groups = {}
    with CANDIDATE_PATH.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            groups.setdefault(int(row["og_id"]), []).append(row)

    all_rows = []
    best_rows = []
    counts = Counter()
    for old_id in sorted(groups):
        rows = sorted(
            groups[old_id],
            key=lambda row: (float(row["ranking_score"]), int(row["ae_rva"], 16)),
            reverse=True,
        )
        best = rows[0] if rows else None
        second = rows[1] if len(rows) > 1 else None
        result_confidence, margin = confidence(best, second) if best else ("unresolved", 0.0)
        counts[result_confidence] += 1
        for rank, row in enumerate(rows, start=1):
            row["rank"] = rank
            row["confidence"] = result_confidence if rank == 1 else "alternative"
            row["margin_to_second"] = "{:.4f}".format(margin) if rank == 1 else ""
            all_rows.append(row)
            if rank == 1:
                best_rows.append(row)

    fields = candidate_fields()
    for path, rows in ((CANDIDATE_PATH, all_rows), (BEST_PATH, best_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    old_lines = SUMMARY_PATH.read_text(encoding="utf-8").splitlines() if SUMMARY_PATH.is_file() else []
    labels = ("Exact unique:", "Strong unique:", "Likely unique:", "Needs review:", "Unresolved:")
    kept = [line for line in old_lines if not line.startswith(labels)]
    insert_at = next((index for index, line in enumerate(kept) if line.startswith("Elapsed seconds:")), len(kept))
    classification_lines = [
        "Exact unique: {}".format(counts["exact_unique"]),
        "Strong unique: {}".format(counts["strong_unique"]),
        "Likely unique: {}".format(counts["likely_unique"]),
        "Needs review: {}".format(counts["review"]),
        "Unresolved: {}".format(counts["unresolved"]),
    ]
    final_lines = kept[:insert_at] + classification_lines + kept[insert_at:]
    SUMMARY_PATH.write_text("\n".join(final_lines) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(classification_lines))


def scan_ae(profiles, imagebase, exporter, csv_index):
    heaps = {profile["og_id"]: [] for profile in profiles}
    functions = [int(ea) for ea in idautils.Functions()]
    started = time.time()
    errors = 0
    compared = 0
    print("[CommonLibF4AE] Scanne {} AE-Funktionen fuer {} OG-Ziele".format(len(functions), len(profiles)))

    for index, ea in enumerate(functions, start=1):
        try:
            candidate = exporter.extract_function(ea)
            candidate_rva = int(candidate.get("start_rva", ea - imagebase))
            csv_rows = candidate_csv_rows(csv_index, candidate_rva)
            for profile in profiles:
                if not eligible(profile, candidate):
                    continue
                ranking_score, raw_score, exact_hash, details = score_candidate(
                    profile, candidate, candidate_rva, csv_rows
                )
                compared += 1
                candidate_row = {
                    "og_id": profile["og_id"],
                    "og_rva": "0x{:X}".format(profile["og_rva"]),
                    "target_name": profile.get("csv_name")
                    or profile["function"].get("demangled_name", ""),
                    "locations": profile.get("locations", ""),
                    "score": raw_score,
                    "ranking_score": ranking_score,
                    "exact_hash": "yes" if exact_hash else "no",
                    "ae_rva": "0x{:X}".format(candidate_rva),
                    "ae_name": candidate.get("demangled_name", candidate.get("raw_name", "")),
                    "existing_ae_ids": ",".join(str(row["ae_id"]) for row in csv_rows),
                    "existing_pair_rows": ",".join(str(row["row"]) for row in csv_rows),
                    "mapped_to_other": "yes" if csv_rows else "no",
                    "name_score": details["name_score"],
                    "size_score": details["size_score"],
                    "instruction_score": details["instruction_score"],
                    "cfg_score": details["cfg_score"],
                    "mnemonic_score": details["mnemonic_score"],
                    "shape_score": details["shape_score"],
                    "calls_score": details["calls_score"],
                    "callers_score": details["callers_score"],
                    "strings_score": details["strings_score"],
                    "member_offsets_score": details["member_offsets_score"],
                }
                heap = heaps[profile["og_id"]]
                item = (ranking_score, candidate_rva, candidate_row)
                if len(heap) < TOP_CANDIDATES:
                    heapq.heappush(heap, item)
                elif item[:2] > heap[0][:2]:
                    heapq.heapreplace(heap, item)
        except Exception:
            errors += 1
        finally:
            exporter.cache.clear()

        if index % PROGRESS_INTERVAL == 0 or index == len(functions):
            print(
                "[CommonLibF4AE] AE {}/{} ({:.1f}%) semantic comparisons={} errors={} elapsed={:.1f}s".format(
                    index,
                    len(functions),
                    index * 100.0 / max(1, len(functions)),
                    compared,
                    errors,
                    time.time() - started,
                )
            )
    return heaps, len(functions), compared, errors, time.time() - started


def main():
    semantic_tools.require_ida()
    side = semantic_tools.detect_side()
    targets = load_targets(TARGET_PATH)
    csv_rows = semantic_tools.load_csv_rows(semantic_tools.CSV_PATH)
    csv_index = semantic_tools.CsvIndex(csv_rows, side)
    imagebase = int(ida_nalt.get_imagebase())
    strings = semantic_tools.load_strings()
    exporter = semantic_tools.SemanticExporter(side, csv_index, imagebase, strings)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if ida_kernwin:
        ida_kernwin.show_wait_box("HIDECANCEL Suche fehlende CommonLib-Relocations ({}) ...".format(side))
    try:
        if side == "og":
            counts = write_og_profiles(targets, imagebase, exporter)
            lines = [
                "CommonLibF4 unmapped OG function profiles",
                "Targets: {}".format(len(targets)),
                "Resolved: {}".format(counts["ok"]),
                "No function: {}".format(counts["no_function"]),
                "Errors: {}".format(counts["error"]),
                "Output: {}".format(OG_PROFILE_PATH),
            ]
            OG_SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        else:
            profiles = load_og_profiles(OG_PROFILE_PATH)
            heaps, function_count, compared, errors, elapsed = scan_ae(
                profiles, imagebase, exporter, csv_index
            )
            counts, best_rows = write_candidates(profiles, heaps)
            lines = [
                "CommonLibF4 unmapped AE function matching",
                "OG profiles: {}".format(len(profiles)),
                "AE functions scanned: {}".format(function_count),
                "Detailed semantic comparisons: {}".format(compared),
                "Scan errors: {}".format(errors),
                "Exact unique: {}".format(counts["exact_unique"]),
                "Strong unique: {}".format(counts["strong_unique"]),
                "Likely unique: {}".format(counts["likely_unique"]),
                "Needs review: {}".format(counts["review"]),
                "Unresolved: {}".format(counts["unresolved"]),
                "Elapsed seconds: {:.3f}".format(elapsed),
                "Best candidates: {}".format(BEST_PATH),
                "All candidates: {}".format(CANDIDATE_PATH),
            ]
            SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        for line in lines:
            print("[CommonLibF4AE] " + line)
    finally:
        if ida_kernwin:
            ida_kernwin.hide_wait_box()

    if idaapi is not None and getattr(idaapi.cvar, "batch", False):
        idc.qexit(0)


if __name__ == "__main__":
    if idaapi is None:
        rerank_existing_candidates()
    else:
        main()
