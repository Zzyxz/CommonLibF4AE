# SPDX-License-Identifier: MIT
"""Compare targeted OG and AE pseudocode exports without modifying either IDB."""

from __future__ import annotations

import csv
import json
import os
import re
from difflib import SequenceMatcher
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = Path(
    os.environ.get("CLF4_SEMANTIC_OUT", str(REPO_ROOT / "build" / "ida-semantic"))
)
OG_PATH = REPORT_DIR / "candidate_decompiles_og.jsonl"
AE_PATH = REPORT_DIR / "candidate_decompiles_ae221.jsonl"
OUTPUT = REPORT_DIR / "candidate_decompile_comparison.csv"
SUMMARY = REPORT_DIR / "candidate_decompile_comparison_summary.txt"

COMMENT = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
ADDRESS_SYMBOL = re.compile(
    r"\b(?:sub|loc|off|unk|byte|word|dword|qword|xmmword)_[0-9A-Fa-f]+\b"
)
NUMBER = re.compile(r"\b(?:0x[0-9A-Fa-f]+|[0-9]+(?:LL|i64|ui64|u)?)\b")
TEMPORARY = re.compile(r"\b(?:v|a|result|this)[0-9]*\b")
WHITESPACE = re.compile(r"\s+")
MNEMONIC = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)")


def load(path: Path) -> dict[int, dict]:
    result = {}
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            if row.get("kind") == "metadata":
                continue
            result[int(row["og_id"])] = row
    return result


def normalize_pseudocode(text: str) -> str:
    text = COMMENT.sub(" ", text or "")
    text = ADDRESS_SYMBOL.sub("SYMBOL", text)
    text = NUMBER.sub("NUMBER", text)
    text = TEMPORARY.sub("VAR", text)
    return WHITESPACE.sub("", text).lower()


def mnemonic_sequence(instructions: list[str]) -> str:
    mnemonics = []
    for instruction in instructions or []:
        match = MNEMONIC.match(instruction)
        if match:
            mnemonics.append(match.group(1).lower())
    return " ".join(mnemonics)


def ratio(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right, autojunk=False).ratio()


def count_ratio(left: int, right: int) -> float:
    return min(left, right) / max(left, right) if left or right else 1.0


def jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left or right else 1.0


def main() -> None:
    og = load(OG_PATH)
    ae = load(AE_PATH)
    if set(og) != set(ae):
        raise RuntimeError("OG and AE candidate sets differ")

    rows = []
    for old_id in sorted(og):
        old = og[old_id]
        new = ae[old_id]
        old_evidence = old["evidence"]
        new_evidence = new["evidence"]
        if old["kind"] == "function":
            pseudocode_ratio = ratio(
                normalize_pseudocode(old_evidence.get("pseudocode", "")),
                normalize_pseudocode(new_evidence.get("pseudocode", "")),
            )
            mnemonic_ratio = ratio(
                mnemonic_sequence(old_evidence.get("instructions", [])),
                mnemonic_sequence(new_evidence.get("instructions", [])),
            )
            size_ratio = count_ratio(
                int(old_evidence.get("size", 0)), int(new_evidence.get("size", 0))
            )
            call_ratio = count_ratio(
                len(old_evidence.get("calls", [])), len(new_evidence.get("calls", []))
            )
            string_jaccard = jaccard(
                set(old_evidence.get("strings", [])),
                set(new_evidence.get("strings", [])),
            )
            combined = (
                0.35 * pseudocode_ratio
                + 0.30 * mnemonic_ratio
                + 0.15 * size_ratio
                + 0.10 * call_ratio
                + 0.10 * string_jaccard
            )
            old_name = old_evidence.get("name", "")
            ae_name = new_evidence.get("name", "")
            old_size = old_evidence.get("size", "")
            ae_size = new_evidence.get("size", "")
        else:
            pseudocode_ratio = ""
            mnemonic_ratio = ""
            size_ratio = ""
            call_ratio = ""
            old_bytes = old_evidence.get("first_64_bytes", "")
            new_bytes = new_evidence.get("first_64_bytes", "")
            string_jaccard = ""
            combined = ratio(old_bytes, new_bytes)
            old_name = old_evidence.get("name", "")
            ae_name = new_evidence.get("name", "")
            old_size = ""
            ae_size = ""

        rows.append(
            {
                "og_id": old_id,
                "official_ae_id": old["official_ae_id"],
                "confidence_tier": old["confidence_tier"],
                "kind": old["kind"],
                "match_evidence": old["match_evidence"],
                "symbol_name": old["symbol_name"],
                "og_rva": old["target_rva"],
                "ae_rva": new["target_rva"],
                "og_name": old_name,
                "ae_name": ae_name,
                "og_size": old_size,
                "ae_size": ae_size,
                "pseudocode_ratio": (
                    f"{pseudocode_ratio:.6f}" if pseudocode_ratio != "" else ""
                ),
                "mnemonic_ratio": (
                    f"{mnemonic_ratio:.6f}" if mnemonic_ratio != "" else ""
                ),
                "size_ratio": f"{size_ratio:.6f}" if size_ratio != "" else "",
                "call_count_ratio": f"{call_ratio:.6f}" if call_ratio != "" else "",
                "string_jaccard": (
                    f"{string_jaccard:.6f}" if string_jaccard != "" else ""
                ),
                "combined_score": f"{combined:.6f}",
            }
        )

    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(
            target,
            fieldnames=list(rows[0]),
            delimiter=";",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    functions = [row for row in rows if row["kind"] == "function"]
    summary = [
        f"Candidates compared: {len(rows)}",
        f"Functions compared: {len(functions)}",
        "Function combined score >= 0.85: {}".format(
            sum(float(row["combined_score"]) >= 0.85 for row in functions)
        ),
        "Function combined score >= 0.70: {}".format(
            sum(float(row["combined_score"]) >= 0.70 for row in functions)
        ),
        "Function combined score < 0.50: {}".format(
            sum(float(row["combined_score"]) < 0.50 for row in functions)
        ),
        f"CSV: {OUTPUT}",
        f"Summary: {SUMMARY}",
    ]
    SUMMARY.write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
