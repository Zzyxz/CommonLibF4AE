# SPDX-License-Identifier: MIT
"""Match unmapped functions through callsite context in confirmed function pairs."""

from __future__ import print_function

import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import ida_export_rel_semantics as semantic_tools
import ida_match_unmapped_globals_context as context_tools


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
TARGET_PATH = REPORT_DIR / "unmapped_rel_targets.csv"
SEMANTIC_BEST_PATH = REPORT_DIR / "unmapped_function_best_candidates.csv"
OG_EVIDENCE_PATH = REPORT_DIR / "unmapped_og_function_call_context.jsonl"
CANDIDATE_PATH = REPORT_DIR / "unmapped_function_context_candidates.csv"
BEST_PATH = REPORT_DIR / "unmapped_function_context_best_candidates.csv"
SUMMARY_PATH = REPORT_DIR / "unmapped_function_context_summary.txt"
OG_SUMMARY_PATH = REPORT_DIR / "unmapped_og_function_call_context_summary.txt"
TOP_CANDIDATES = 10


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
    result = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            if row["kind"] != "function" or int(row["og_id"]) == context_tools.TYPEINFO_FUNCTION_POINTER_ID:
                continue
            result.append(
                {
                    "og_id": int(row["og_id"]),
                    "og_rva": parse_hex(row["og_rva"]),
                    "csv_name": row["csv_name"],
                    "locations": row["locations"],
                }
            )
    return result


def export_og_evidence(targets, imagebase, csv_index):
    contexts = context_tools.FunctionContexts(imagebase)
    total_xrefs = 0
    paired_xrefs = 0
    no_anchor = 0
    with OG_EVIDENCE_PATH.open("w", encoding="utf-8", newline="\n") as output:
        output.write(
            json.dumps(
                {
                    "kind": "metadata",
                    "format": "CommonLibF4-function-context-v1",
                    "target_count": len(targets),
                    "imagebase": imagebase,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        for target in targets:
            target_ea = imagebase + target["og_rva"]
            xrefs = []
            raw_count = 0
            for source_ea in idautils.CodeRefsTo(target_ea, False):
                raw_count += 1
                source_ea = int(source_ea)
                function = ida_funcs.get_func(source_ea)
                if function is None:
                    continue
                caller_rva = int(function.start_ea) - imagebase
                rows = context_tools.complete_rows(csv_index.rows_for_rva(caller_rva))
                if not rows:
                    continue
                context = contexts.at(int(function.start_ea), source_ea)
                if context is None:
                    continue
                for row in rows:
                    entry = dict(context)
                    entry.update(
                        {
                            "pair_row": row["row"],
                            "og_caller_rva": row["og_rva"],
                            "ae_caller_rva": row["ae_rva"],
                            "og_caller_id": row["og_id"],
                            "ae_caller_id": row["ae_id"],
                            "source_rva": source_ea - imagebase,
                        }
                    )
                    xrefs.append(entry)
            total_xrefs += raw_count
            paired_xrefs += len(xrefs)
            if not xrefs:
                no_anchor += 1
            record = dict(target)
            record.update(
                {
                    "kind": "function_target",
                    "og_name": str(idc.get_name(target_ea) or ""),
                    "raw_xref_count": raw_count,
                    "paired_xrefs": xrefs,
                }
            )
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return total_xrefs, paired_xrefs, no_anchor


def load_evidence(path):
    result = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            if record.get("kind") == "function_target":
                result.append(record)
    return result


def load_semantic_best(path):
    result = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            result[int(row["og_id"])] = row
    return result


def code_accesses(contexts, function_start, imagebase):
    context = contexts.get(function_start)
    accesses = []
    for index, ea in enumerate(context["items"]):
        mnemonic = context["mnemonics"][index]
        if not (mnemonic.startswith("call") or mnemonic == "jmp"):
            continue
        refs = [int(target) for target in idautils.CodeRefsFrom(ea, False)]
        start = max(0, index - context_tools.WINDOW_RADIUS)
        end = min(len(context["items"]), index + context_tools.WINDOW_RADIUS + 1)
        for target in refs:
            target_function = ida_funcs.get_func(target)
            target_ea = int(target_function.start_ea) if target_function else target
            if target_function and int(target_function.start_ea) == int(function_start):
                continue
            accesses.append(
                {
                    "instruction_index": index,
                    "instruction_count": len(context["items"]),
                    "position": index / float(max(1, len(context["items"]) - 1)),
                    "mnemonic": mnemonic,
                    "signature": context["signatures"][index],
                    "window": context["signatures"][start:end],
                    "target_rva": target_ea - imagebase,
                    "target_name": str(idc.get_name(target_ea) or ""),
                }
            )
    return accesses


def existing_ae_ids(csv_index, rva):
    rows = context_tools.complete_rows(csv_index.rows_for_rva(rva))
    return ",".join(str(row["ae_id"]) for row in rows)


def classify(best, second):
    if best is None:
        return "unresolved", 0.0, 0.0
    score = float(best["vote_score"])
    second_score = float(second["vote_score"]) if second else 0.0
    margin = score - second_score
    ratio = score / second_score if second_score > 0 else (999.0 if score > 0 else 0.0)
    agrees = best["agrees_with_semantic"] == "yes"
    if agrees and int(best["exact_pair_calls"]) >= 1 and ratio >= 1.2:
        return "confirmed_agreement", margin, ratio
    if int(best["exact_pair_calls"]) >= 1 and ratio >= 1.4 and margin >= 0.5:
        return "strong_exact_context", margin, ratio
    if agrees and int(best["unique_pair_rows"]) >= 2 and ratio >= 1.3:
        return "strong_agreement", margin, ratio
    if int(best["unique_pair_rows"]) >= 3 and ratio >= 1.5 and margin >= 1.0:
        return "strong_context", margin, ratio
    if int(best["unique_pair_rows"]) >= 2 and ratio >= 1.5 and margin >= 0.5:
        return "likely_context", margin, ratio
    if agrees and int(best["matched_calls"]) >= 1 and float(best["average_context_score"]) >= 0.85:
        return "likely_agreement", margin, ratio
    return "review", margin, ratio


def match_ae(evidence, imagebase, csv_index):
    pair_quality = context_tools.load_pair_quality(context_tools.PAIR_COMPARISON_PATH)
    semantic_best = load_semantic_best(SEMANTIC_BEST_PATH)
    contexts = context_tools.FunctionContexts(imagebase)
    access_cache = {}
    all_rows = []
    best_rows = []
    counts = Counter()
    processed_calls = 0
    started = time.time()

    for target_index, target in enumerate(evidence, start=1):
        votes = Counter()
        matches = Counter()
        exact_matches = Counter()
        pair_rows = defaultdict(set)
        descriptors = {}
        context_sums = Counter()

        for old_call in target.get("paired_xrefs", []):
            processed_calls += 1
            caller_ea = imagebase + int(old_call["ae_caller_rva"])
            caller_function = ida_funcs.get_func(caller_ea)
            if caller_function is None:
                continue
            caller_start = int(caller_function.start_ea)
            if caller_start not in access_cache:
                access_cache[caller_start] = code_accesses(contexts, caller_start, imagebase)
            quality = pair_quality.get(int(old_call["pair_row"]), {"score": 0.5, "exact": False})
            scored = []
            for access in access_cache[caller_start]:
                score = context_tools.context_similarity(old_call, access, quality)
                scored.append((score, int(access["target_rva"]), access))
            if not scored:
                continue
            scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
            top_score = scored[0][0]
            if top_score < 0.58:
                continue
            top_candidates = [item for item in scored if top_score - item[0] <= 0.015]
            unique_targets = {item[1] for item in top_candidates}
            if len(unique_targets) != 1:
                continue
            _score, candidate_rva, descriptor = top_candidates[0]
            weight = top_score * (1.5 if quality.get("exact") else max(0.5, quality.get("score", 0.5)))
            votes[candidate_rva] += weight
            matches[candidate_rva] += 1
            context_sums[candidate_rva] += top_score
            pair_rows[candidate_rva].add(int(old_call["pair_row"]))
            if quality.get("exact"):
                exact_matches[candidate_rva] += 1
            descriptors[candidate_rva] = descriptor

        semantic = semantic_best.get(int(target["og_id"]), {})
        semantic_rva = parse_hex(semantic.get("ae_rva"))
        ranked = []
        for candidate_rva, vote_score in votes.items():
            descriptor = descriptors[candidate_rva]
            ranked.append(
                {
                    "og_id": target["og_id"],
                    "og_rva": "0x{:X}".format(int(target["og_rva"])),
                    "target_name": target.get("csv_name") or target.get("og_name", ""),
                    "locations": target.get("locations", ""),
                    "raw_xref_count": target.get("raw_xref_count", 0),
                    "paired_call_count": len(target.get("paired_xrefs", [])),
                    "matched_calls": matches[candidate_rva],
                    "exact_pair_calls": exact_matches[candidate_rva],
                    "unique_pair_rows": len(pair_rows[candidate_rva]),
                    "vote_score": "{:.6f}".format(vote_score),
                    "average_context_score": "{:.4f}".format(
                        context_sums[candidate_rva] / max(1, matches[candidate_rva])
                    ),
                    "ae_rva": "0x{:X}".format(candidate_rva),
                    "ae_name": descriptor.get("target_name", ""),
                    "existing_ae_ids": existing_ae_ids(csv_index, candidate_rva),
                    "semantic_best_rva": "" if semantic_rva is None else "0x{:X}".format(semantic_rva),
                    "semantic_score": semantic.get("score", ""),
                    "semantic_confidence": semantic.get("confidence", ""),
                    "agrees_with_semantic": "yes" if semantic_rva == candidate_rva else "no",
                }
            )
        ranked.sort(
            key=lambda row: (
                float(row["vote_score"]),
                int(row["unique_pair_rows"]),
                float(row["average_context_score"]),
            ),
            reverse=True,
        )
        ranked = ranked[:TOP_CANDIDATES]
        best = ranked[0] if ranked else None
        second = ranked[1] if len(ranked) > 1 else None
        result_class, margin, ratio = classify(best, second)
        counts[result_class] += 1
        if best is None:
            best_rows.append(
                {
                    "og_id": target["og_id"],
                    "og_rva": "0x{:X}".format(int(target["og_rva"])),
                    "target_name": target.get("csv_name") or target.get("og_name", ""),
                    "locations": target.get("locations", ""),
                    "confidence": "unresolved",
                    "raw_xref_count": target.get("raw_xref_count", 0),
                    "paired_call_count": len(target.get("paired_xrefs", [])),
                    "semantic_best_rva": "" if semantic_rva is None else "0x{:X}".format(semantic_rva),
                    "semantic_score": semantic.get("score", ""),
                    "semantic_confidence": semantic.get("confidence", ""),
                }
            )
        for rank, row in enumerate(ranked, start=1):
            row["rank"] = rank
            row["confidence"] = result_class if rank == 1 else "alternative"
            row["margin_to_second"] = "{:.6f}".format(margin) if rank == 1 else ""
            row["ratio_to_second"] = "{:.4f}".format(ratio) if rank == 1 else ""
            all_rows.append(row)
            if rank == 1:
                best_rows.append(row)

        if target_index % 10 == 0 or target_index == len(evidence):
            print(
                "[CommonLibF4AE] Function call context {}/{} calls={} cached_callers={} elapsed={:.1f}s".format(
                    target_index,
                    len(evidence),
                    processed_calls,
                    len(access_cache),
                    time.time() - started,
                )
            )
    return all_rows, best_rows, counts, processed_calls, len(access_cache), time.time() - started


def write_reports(all_rows, best_rows):
    fields = [
        "og_id",
        "og_rva",
        "target_name",
        "locations",
        "rank",
        "confidence",
        "raw_xref_count",
        "paired_call_count",
        "matched_calls",
        "exact_pair_calls",
        "unique_pair_rows",
        "vote_score",
        "margin_to_second",
        "ratio_to_second",
        "average_context_score",
        "ae_rva",
        "ae_name",
        "existing_ae_ids",
        "semantic_best_rva",
        "semantic_score",
        "semantic_confidence",
        "agrees_with_semantic",
    ]
    for path, rows in ((CANDIDATE_PATH, all_rows), (BEST_PATH, best_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)


def main():
    semantic_tools.require_ida()
    side = semantic_tools.detect_side()
    targets = load_targets(TARGET_PATH)
    csv_rows = semantic_tools.load_csv_rows(semantic_tools.CSV_PATH)
    csv_index = semantic_tools.CsvIndex(csv_rows, side)
    imagebase = int(ida_nalt.get_imagebase())

    if ida_kernwin:
        ida_kernwin.show_wait_box("HIDECANCEL Vergleiche fehlende Funktions-Callsites ({}) ...".format(side))
    try:
        if side == "og":
            raw_xrefs, paired_xrefs, no_anchor = export_og_evidence(targets, imagebase, csv_index)
            lines = [
                "CommonLibF4 OG missing-function call context",
                "Targets: {}".format(len(targets)),
                "Raw call xrefs: {}".format(raw_xrefs),
                "Paired call anchors: {}".format(paired_xrefs),
                "Targets without paired caller: {}".format(no_anchor),
                "Output: {}".format(OG_EVIDENCE_PATH),
            ]
            OG_SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        else:
            evidence = load_evidence(OG_EVIDENCE_PATH)
            all_rows, best_rows, counts, calls, cached, elapsed = match_ae(
                evidence, imagebase, csv_index
            )
            write_reports(all_rows, best_rows)
            lines = [
                "CommonLibF4 AE missing-function call-context matching",
                "Targets: {}".format(len(evidence)),
                "Paired calls processed: {}".format(calls),
                "AE caller functions inspected: {}".format(cached),
                "Confirmed semantic/context agreement: {}".format(counts["confirmed_agreement"]),
                "Strong exact context: {}".format(counts["strong_exact_context"]),
                "Strong agreement: {}".format(counts["strong_agreement"]),
                "Strong context: {}".format(counts["strong_context"]),
                "Likely context: {}".format(counts["likely_context"]),
                "Likely agreement: {}".format(counts["likely_agreement"]),
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
    main()
