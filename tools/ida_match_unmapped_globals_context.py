# SPDX-License-Identifier: MIT
"""Match unmapped global RVAs by instruction-context xrefs in paired functions."""

from __future__ import print_function

import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import ida_export_rel_semantics as semantic_tools


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
TARGET_PATH = REPORT_DIR / "unmapped_rel_targets.csv"
PAIR_COMPARISON_PATH = REPORT_DIR / "rel_semantic_comparison.csv"
OG_EVIDENCE_PATH = REPORT_DIR / "unmapped_og_global_xref_context.jsonl"
CANDIDATE_PATH = REPORT_DIR / "unmapped_global_context_candidates.csv"
BEST_PATH = REPORT_DIR / "unmapped_global_context_best_candidates.csv"
SUMMARY_PATH = REPORT_DIR / "unmapped_global_context_summary.txt"
OG_SUMMARY_PATH = REPORT_DIR / "unmapped_og_global_xref_context_summary.txt"
TYPEINFO_FUNCTION_POINTER_ID = 1419793
TOP_CANDIDATES = 10
WINDOW_RADIUS = 3
PROGRESS_INTERVAL = 5000


try:
    import idaapi
    import ida_funcs
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_ua = None
    idautils = None
    idc = None


def parse_hex(value):
    text = str(value or "").strip()
    return int(text, 16) if text else None


def load_targets(path):
    targets = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            old_id = int(row["og_id"])
            if row["kind"] == "function" and old_id != TYPEINFO_FUNCTION_POINTER_ID:
                continue
            targets.append(
                {
                    "og_id": old_id,
                    "og_rva": parse_hex(row["og_rva"]),
                    "locations": row["locations"],
                }
            )
    return targets


def complete_rows(rows):
    return [
        row
        for row in rows
        if row.get("og_rva") is not None
        and row.get("og_id") is not None
        and row.get("ae_rva") is not None
        and row.get("ae_id") is not None
    ]


def instruction_signature(ea):
    mnemonic = str(idc.print_insn_mnem(ea) or "").lower()
    shapes = []
    for operand_index in range(8):
        op_type = int(idc.get_operand_type(ea, operand_index))
        if op_type == getattr(ida_ua, "o_void", 0):
            break
        shapes.append(semantic_tools.operand_kind(op_type))
    return mnemonic, "{}:{}".format(mnemonic, ",".join(shapes))


class FunctionContexts(object):
    def __init__(self, imagebase):
        self.imagebase = imagebase
        self.cache = {}

    def get(self, function_start):
        function_start = int(function_start)
        if function_start in self.cache:
            return self.cache[function_start]
        items = [int(ea) for ea in idautils.FuncItems(function_start)]
        signatures = []
        mnemonics = []
        for ea in items:
            mnemonic, signature = instruction_signature(ea)
            mnemonics.append(mnemonic)
            signatures.append(signature)
        by_ea = {ea: index for index, ea in enumerate(items)}
        context = {
            "items": items,
            "signatures": signatures,
            "mnemonics": mnemonics,
            "by_ea": by_ea,
        }
        self.cache[function_start] = context
        return context

    def at(self, function_start, source_ea):
        context = self.get(function_start)
        index = context["by_ea"].get(int(source_ea))
        if index is None:
            return None
        start = max(0, index - WINDOW_RADIUS)
        end = min(len(context["items"]), index + WINDOW_RADIUS + 1)
        return {
            "instruction_index": index,
            "instruction_count": len(context["items"]),
            "position": index / float(max(1, len(context["items"]) - 1)),
            "mnemonic": context["mnemonics"][index],
            "signature": context["signatures"][index],
            "window": context["signatures"][start:end],
        }

    def data_accesses(self, function_start, imagebase):
        context = self.get(function_start)
        accesses = []
        for index, ea in enumerate(context["items"]):
            refs = [int(target) for target in idautils.DataRefsFrom(ea)]
            if not refs:
                continue
            start = max(0, index - WINDOW_RADIUS)
            end = min(len(context["items"]), index + WINDOW_RADIUS + 1)
            for target in refs:
                accesses.append(
                    {
                        "instruction_index": index,
                        "instruction_count": len(context["items"]),
                        "position": index / float(max(1, len(context["items"]) - 1)),
                        "mnemonic": context["mnemonics"][index],
                        "signature": context["signatures"][index],
                        "window": context["signatures"][start:end],
                        "target_rva": target - imagebase,
                        "target_name": str(idc.get_name(target) or ""),
                        "target_segment": semantic_tools.segment_name(target),
                    }
                )
        return accesses


def export_og_evidence(targets, imagebase, csv_index):
    contexts = FunctionContexts(imagebase)
    total_xrefs = 0
    total_anchors = 0
    no_anchor = 0
    with OG_EVIDENCE_PATH.open("w", encoding="utf-8", newline="\n") as output:
        output.write(
            json.dumps(
                {
                    "kind": "metadata",
                    "format": "CommonLibF4-global-context-v1",
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
            raw_xrefs = 0
            for source_ea in idautils.DataRefsTo(target_ea):
                raw_xrefs += 1
                source_ea = int(source_ea)
                function = ida_funcs.get_func(source_ea)
                if function is None:
                    continue
                function_rva = int(function.start_ea) - imagebase
                rows = complete_rows(csv_index.rows_for_rva(function_rva))
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
                            "og_function_rva": row["og_rva"],
                            "ae_function_rva": row["ae_rva"],
                            "og_function_id": row["og_id"],
                            "ae_function_id": row["ae_id"],
                            "source_rva": source_ea - imagebase,
                        }
                    )
                    xrefs.append(entry)
            total_xrefs += raw_xrefs
            total_anchors += len(xrefs)
            if not xrefs:
                no_anchor += 1
            record = dict(target)
            record.update(
                {
                    "kind": "global_target",
                    "og_name": str(idc.get_name(target_ea) or ""),
                    "og_segment": semantic_tools.segment_name(target_ea),
                    "raw_xref_count": raw_xrefs,
                    "paired_xrefs": xrefs,
                }
            )
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return total_xrefs, total_anchors, no_anchor


def load_og_evidence(path):
    result = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            if record.get("kind") == "global_target":
                result.append(record)
    return result


def load_pair_quality(path):
    result = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source, delimiter=";"):
            result[int(row["csv_row"])] = {
                "score": float(row["score"]),
                "exact": row["exact_semantic_hash"] == "yes",
            }
    return result


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


def context_similarity(old, new, pair_quality):
    signature_score = SequenceMatcher(None, old["signature"], new["signature"]).ratio()
    window_score = SequenceMatcher(None, old["window"], new["window"]).ratio()
    position_score = max(0.0, 1.0 - abs(float(old["position"]) - float(new["position"])))
    mnemonic_score = 1.0 if old["mnemonic"] == new["mnemonic"] else 0.0
    score = (
        0.40 * signature_score
        + 0.35 * window_score
        + 0.20 * position_score
        + 0.05 * mnemonic_score
    )
    if pair_quality.get("exact") and old["instruction_index"] == new["instruction_index"]:
        score = min(1.0, score + 0.15)
    return score


def generic_name(name):
    return not name or bool(
        re.match(r"^(?:qword|dword|word|byte|unk|off|stru|asc|loc|sub)_[0-9A-Fa-f]+$", str(name))
    )


def name_similarity(left, right):
    if generic_name(left) or generic_name(right):
        return 0.0
    left = re.sub(r"[^a-z0-9_]+", "", str(left).lower())
    right = re.sub(r"[^a-z0-9_]+", "", str(right).lower())
    return SequenceMatcher(None, left, right).ratio() if left and right else 0.0


def classify(best, second):
    if best is None:
        return "unresolved", 0.0, 0.0
    score = float(best["vote_score"])
    second_score = float(second["vote_score"]) if second else 0.0
    margin = score - second_score
    ratio = score / second_score if second_score > 0 else (999.0 if score > 0 else 0.0)
    if float(best["name_score"]) >= 0.85 and int(best["matched_xrefs"]) >= 1:
        return "strong_name", margin, ratio
    if int(best["exact_pair_xrefs"]) >= 1 and ratio >= 1.3 and margin >= 0.5:
        return "strong_exact_context", margin, ratio
    if int(best["unique_pair_rows"]) >= 3 and ratio >= 1.5 and margin >= 1.0:
        return "strong_context", margin, ratio
    if int(best["unique_pair_rows"]) >= 2 and ratio >= 1.5 and margin >= 0.5:
        return "likely_context", margin, ratio
    if int(best["matched_xrefs"]) == 1 and float(best["average_context_score"]) >= 0.90 and ratio >= 1.5:
        return "single_context", margin, ratio
    return "review", margin, ratio


def match_ae(evidence, imagebase):
    pair_quality = load_pair_quality(PAIR_COMPARISON_PATH)
    contexts = FunctionContexts(imagebase)
    access_cache = {}
    all_rows = []
    best_rows = []
    counts = Counter()
    processed_xrefs = 0
    started = time.time()

    for target_index, target in enumerate(evidence, start=1):
        target_segment_class = segment_class(target.get("og_segment", ""))
        votes = Counter()
        matched_xrefs = Counter()
        exact_pair_xrefs = Counter()
        pair_rows = defaultdict(set)
        descriptors = {}
        context_score_sum = Counter()

        for old_xref in target.get("paired_xrefs", []):
            processed_xrefs += 1
            function_ea = imagebase + int(old_xref["ae_function_rva"])
            function = ida_funcs.get_func(function_ea)
            if function is None:
                continue
            function_start = int(function.start_ea)
            if function_start not in access_cache:
                access_cache[function_start] = contexts.data_accesses(function_start, imagebase)
            quality = pair_quality.get(int(old_xref["pair_row"]), {"score": 0.5, "exact": False})
            scored = []
            for access in access_cache[function_start]:
                if target_segment_class and segment_class(access["target_segment"]) != target_segment_class:
                    continue
                score = context_similarity(old_xref, access, quality)
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
            matched_xrefs[candidate_rva] += 1
            context_score_sum[candidate_rva] += top_score
            pair_rows[candidate_rva].add(int(old_xref["pair_row"]))
            if quality.get("exact"):
                exact_pair_xrefs[candidate_rva] += 1
            descriptors[candidate_rva] = descriptor

        ranked = []
        for candidate_rva, vote_score in votes.items():
            descriptor = descriptors[candidate_rva]
            ranked.append(
                {
                    "og_id": target["og_id"],
                    "og_rva": "0x{:X}".format(int(target["og_rva"])),
                    "og_name": target.get("og_name", ""),
                    "og_segment": target.get("og_segment", ""),
                    "locations": target.get("locations", ""),
                    "raw_xref_count": target.get("raw_xref_count", 0),
                    "paired_xref_count": len(target.get("paired_xrefs", [])),
                    "matched_xrefs": matched_xrefs[candidate_rva],
                    "exact_pair_xrefs": exact_pair_xrefs[candidate_rva],
                    "unique_pair_rows": len(pair_rows[candidate_rva]),
                    "vote_score": "{:.6f}".format(vote_score),
                    "average_context_score": "{:.4f}".format(
                        context_score_sum[candidate_rva] / max(1, matched_xrefs[candidate_rva])
                    ),
                    "name_score": "{:.4f}".format(
                        name_similarity(target.get("og_name", ""), descriptor.get("target_name", ""))
                    ),
                    "ae_rva": "0x{:X}".format(candidate_rva),
                    "ae_name": descriptor.get("target_name", ""),
                    "ae_segment": descriptor.get("target_segment", ""),
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
                    "og_name": target.get("og_name", ""),
                    "og_segment": target.get("og_segment", ""),
                    "locations": target.get("locations", ""),
                    "confidence": "unresolved",
                    "raw_xref_count": target.get("raw_xref_count", 0),
                    "paired_xref_count": len(target.get("paired_xrefs", [])),
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
                "[CommonLibF4AE] Global context {}/{} xrefs={} cached_functions={} elapsed={:.1f}s".format(
                    target_index,
                    len(evidence),
                    processed_xrefs,
                    len(access_cache),
                    time.time() - started,
                )
            )
    return all_rows, best_rows, counts, processed_xrefs, len(access_cache), time.time() - started


def write_reports(all_rows, best_rows):
    fields = [
        "og_id",
        "og_rva",
        "og_name",
        "og_segment",
        "locations",
        "rank",
        "confidence",
        "raw_xref_count",
        "paired_xref_count",
        "matched_xrefs",
        "exact_pair_xrefs",
        "unique_pair_rows",
        "vote_score",
        "margin_to_second",
        "ratio_to_second",
        "average_context_score",
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


def main():
    semantic_tools.require_ida()
    side = semantic_tools.detect_side()
    targets = load_targets(TARGET_PATH)
    csv_rows = semantic_tools.load_csv_rows(semantic_tools.CSV_PATH)
    csv_index = semantic_tools.CsvIndex(csv_rows, side)
    imagebase = int(ida_nalt.get_imagebase())

    if ida_kernwin:
        ida_kernwin.show_wait_box("HIDECANCEL Vergleiche Global-Xref-Kontexte ({}) ...".format(side))
    try:
        if side == "og":
            total_xrefs, total_anchors, no_anchor = export_og_evidence(
                targets, imagebase, csv_index
            )
            lines = [
                "CommonLibF4 OG global xref context",
                "Targets: {}".format(len(targets)),
                "Raw data xrefs: {}".format(total_xrefs),
                "Paired xref anchors: {}".format(total_anchors),
                "Targets without paired anchors: {}".format(no_anchor),
                "Output: {}".format(OG_EVIDENCE_PATH),
            ]
            OG_SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        else:
            evidence = load_og_evidence(OG_EVIDENCE_PATH)
            all_rows, best_rows, counts, xrefs, cached, elapsed = match_ae(
                evidence, imagebase
            )
            write_reports(all_rows, best_rows)
            lines = [
                "CommonLibF4 AE global xref-context matching",
                "Targets: {}".format(len(evidence)),
                "Paired xrefs processed: {}".format(xrefs),
                "AE anchor functions inspected: {}".format(cached),
                "Strong by name: {}".format(counts["strong_name"]),
                "Strong exact context: {}".format(counts["strong_exact_context"]),
                "Strong context: {}".format(counts["strong_context"]),
                "Likely context: {}".format(counts["likely_context"]),
                "Single context: {}".format(counts["single_context"]),
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
