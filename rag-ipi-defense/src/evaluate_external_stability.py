"""Evaluate the frozen BIPIA-calibrated Tier-1 Gate on external IPI suites."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from embedding_intent import EmbeddingConfig, EmbeddingIntentScorer
from main_pipeline import percentile
from srs_score import SRSConfig, compute_srs
from tier2_mac import has_directive_candidate


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return [0.0 if lower < 1e-15 else lower, 1.0 if 1 - upper < 1e-15 else upper]


def summarize(rows: list[dict]) -> dict:
    decisions = Counter(row["decision"] for row in rows)
    pass_n = decisions["PASS"]
    return {
        "n": len(rows),
        "pass_rate": pass_n / len(rows) if rows else None,
        "pass_rate_wilson_ci95": wilson(pass_n, len(rows)),
        "review_rate": decisions["REVIEW"] / len(rows) if rows else None,
        "block_rate": decisions["BLOCK"] / len(rows) if rows else None,
        "candidate_rate": sum(row["directive_candidate"] for row in rows) / len(rows) if rows else None,
        "srs_mean": statistics.fmean(row["srs"] for row in rows) if rows else None,
        "srs_p50": percentile([row["srs"] for row in rows], 0.5),
        "srs_p95": percentile([row["srs"] for row in rows], 0.95),
    }


def injecagent_pair_stability(rows: list[dict]) -> dict:
    pairs: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in rows:
        if row["source"] == "InjecAgent" and row["label"] == "malicious":
            pairs[row["pair_id"]][row["suite"]] = row
    complete = [pair for pair in pairs.values() if {"base", "enhanced"} <= set(pair)]
    agreement = sum(pair["base"]["decision"] == pair["enhanced"]["decision"] for pair in complete)
    robust = sum(pair["base"]["decision"] != "PASS" and pair["enhanced"]["decision"] != "PASS" for pair in complete)
    deltas = [pair["enhanced"]["srs"] - pair["base"]["srs"] for pair in complete]
    return {
        "paired_n": len(complete),
        "decision_agreement": agreement / len(complete),
        "robust_non_pass_both_rate": robust / len(complete),
        "enhanced_minus_base_srs_mean": statistics.fmean(deltas),
        "enhanced_minus_base_srs_abs_mean": statistics.fmean(abs(value) for value in deltas),
    }


def houyi_robustness(rows: list[dict]) -> dict:
    malicious = [row for row in rows if row["source"] == "HouYi" and row["label"] == "malicious"]
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in malicious:
        groups[row["pair_id"]].append(row)
    all_intercepted = sum(all(row["decision"] != "PASS" for row in group) for group in groups.values())
    by_separator = {
        name: summarize([row for row in malicious if row["separator"] == name])
        for name in sorted({row["separator"] for row in malicious})
    }
    by_intention = {
        name: summarize([row for row in malicious if row["attack_family"] == name])
        for name in sorted({row["attack_family"] for row in malicious})
    }
    return {
        "variant_groups": len(groups),
        "all_15_variants_intercepted_rate": all_intercepted / len(groups),
        "worst_separator_pass_rate": max(item["pass_rate"] for item in by_separator.values()),
        "best_separator_pass_rate": min(item["pass_rate"] for item in by_separator.values()),
        "by_separator": by_separator,
        "by_intention": by_intention,
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", nargs="+", type=Path, default=[root / "data" / "external_stability" / "injecagent.jsonl", root / "data" / "external_stability" / "houyi_seed.jsonl"])
    parser.add_argument("--calibration", type=Path, default=root / "results" / "calibration" / "calibration.json")
    parser.add_argument("--gate-calibration", type=Path, default=root / "results" / "gate-calibration-v2" / "calibration.json")
    parser.add_argument("--embedding-cache", type=Path, default=root / "data" / "cache" / "embedding.sqlite3")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "external-stability")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = [row for path in args.data for row in read_jsonl(path)]
    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    gate = json.loads(args.gate_calibration.read_text(encoding="utf-8"))
    srs_config = SRSConfig(**calibration["srs_config"])
    embedding = calibration["embedding"]
    scorer = EmbeddingIntentScorer(EmbeddingConfig(
        model_id=embedding["model_id"], revision=embedding["revision"],
        onnx_filename=embedding["onnx_filename"], max_length=embedding["max_length"],
        max_chunk_chars=embedding["max_chunk_chars"], cache_path=str(args.embedding_cache),
    ))
    low = float(gate["selected"]["tau_low"])
    high = float(gate["selected"]["tau_high"])
    predictions = []
    for index, row in enumerate(rows, 1):
        srs = compute_srs(row["xuser"], row["xext"], srs_config, intent_scorer=scorer)
        candidate = has_directive_candidate(row["xext"])
        if srs["srs"] > high:
            decision = "BLOCK"
        elif candidate or srs["srs"] >= low:
            decision = "REVIEW"
        else:
            decision = "PASS"
        predictions.append({
            **{key: row.get(key) for key in ("id", "pair_id", "source", "suite", "label", "attack_family", "attack_class", "separator", "disruptor")},
            "decision": decision, "srs": srs["srs"], "intent_shift": srs["intent_shift"],
            "instruction_density": srs["instruction_density"], "pressure_signal": srs["pressure_signal"],
            "directive_candidate": candidate,
        })
        if index % 100 == 0 or index == len(rows):
            print(f"Scored {index}/{len(rows)} external stability rows", flush=True)
    report = {
        "scope": "External Tier-1 Gate stability only; frozen BIPIA calibration; PASS rate is an escape proxy, not downstream ASR.",
        "rows": len(predictions),
        "gate": {"tau_low": low, "tau_high": high, "weights": gate["weights"]},
        "overall": {
            source: {
                label: summarize([row for row in predictions if row["source"] == source and row["label"] == label])
                for label in ("malicious", "benign")
            }
            for source in ("InjecAgent", "HouYi")
        },
        "injecagent_suites": {
            suite: summarize([row for row in predictions if row["source"] == "InjecAgent" and row["suite"] == suite])
            for suite in ("base", "enhanced", "clean")
        },
        "injecagent_pair_stability": injecagent_pair_stability(predictions),
        "houyi_seed_stability": houyi_robustness(predictions),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (args.output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with (args.output_dir / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "source", "suite", "label", "n", "pass_rate", "pass_rate_ci95_low",
            "pass_rate_ci95_high", "review_rate", "block_rate", "candidate_rate",
            "srs_mean", "srs_p50", "srs_p95",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for source in ("InjecAgent", "HouYi"):
            suites = sorted({row["suite"] for row in predictions if row["source"] == source})
            for suite in suites:
                for label in ("malicious", "benign"):
                    selected = [row for row in predictions if row["source"] == source and row["suite"] == suite and row["label"] == label]
                    if selected:
                        metrics = summarize(selected)
                        interval = metrics.pop("pass_rate_wilson_ci95")
                        writer.writerow({
                            "source": source,
                            "suite": suite,
                            "label": label,
                            "pass_rate_ci95_low": interval[0] if interval else None,
                            "pass_rate_ci95_high": interval[1] if interval else None,
                            **metrics,
                        })
    print(json.dumps(report, ensure_ascii=False, indent=2))
    scorer.close()


if __name__ == "__main__":
    main()
