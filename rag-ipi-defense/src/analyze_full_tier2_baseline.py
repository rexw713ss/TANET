"""Compare the always-on Tier-2 run with the frozen no-defense/two-stage run."""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path

from downstream_rag import paired_comparisons, percentile, summarize


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def latency(rows: list[dict]) -> dict:
    values = [float(row["detector_latency_ms"]) for row in rows]
    return {
        "mean_ms": statistics.fmean(values),
        "p50_ms": percentile(values, 0.5),
        "p95_ms": percentile(values, 0.95),
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    main_rows = read_jsonl(root / "results" / "main-holdout-v4" / "predictions.jsonl")
    full_rows = read_jsonl(root / "results" / "full-tier2-baseline" / "predictions.jsonl")
    if len(full_rows) != 100 or {row["method"] for row in full_rows} != {"full_tier2"}:
        raise RuntimeError("Full Tier-2 baseline must contain exactly 100 completed rows")
    frozen = [row for row in main_rows if row["method"] in {"no_defense", "two_stage"}]
    expected_ids = {row["id"] for row in frozen if row["method"] == "no_defense"}
    if {row["id"] for row in full_rows} != expected_ids:
        raise RuntimeError("Full Tier-2 IDs do not match the frozen main holdout")
    combined = frozen + full_rows
    methods = ("no_defense", "two_stage", "full_tier2")
    metrics = {method: summarize([row for row in combined if row["method"] == method]) for method in methods}
    baseline_utility = metrics["no_defense"]["benign_task_utility"]
    for method in methods:
        metrics[method]["utility_preservation"] = metrics[method]["benign_task_utility"] / baseline_utility
    comparison = paired_comparisons(combined)
    two_rows = [row for row in frozen if row["method"] == "two_stage"]
    full_latency = latency(full_rows)
    two_latency = latency(two_rows)
    report = {
        "scope": "Same 100 frozen BIPIA IDs; always-on v3 Tier-2 versus candidate-routed two-stage and frozen no-defense.",
        "metrics": metrics,
        "paired_vs_no_defense": comparison,
        "routing_cost": {
            "full_tier2_trigger_rate": 1.0,
            "two_stage_trigger_rate": metrics["two_stage"]["tier2_trigger_rate"],
            "tier2_call_reduction": 1 - metrics["two_stage"]["tier2_trigger_rate"],
            "full_tier2_detector_latency": full_latency,
            "two_stage_detector_latency": two_latency,
            "mean_detector_latency_ratio_full_over_routed": full_latency["mean_ms"] / two_latency["mean_ms"],
        },
        "limitations": [
            "Runs were sequential rather than interleaved; model residency and embedding cache can affect latency.",
            "This is a local Gemma structured-judge baseline, not a commercial guard or a larger safety model.",
            "Generation is skipped after BLOCK, so end-to-end generation cost depends on each method's block rate.",
        ],
    }
    output = root / "results" / "full-tier2-baseline"
    (output / "comparison_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with (output / "comparison_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "method", "attack_success_rate", "benign_task_utility", "utility_preservation",
            "benign_block_rate", "malicious_block_rate", "tier2_trigger_rate",
            "detector_latency_mean_ms", "detector_latency_p50_ms", "detector_latency_p95_ms",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for method in methods:
            rows = [row for row in combined if row["method"] == method]
            timing = latency(rows)
            writer.writerow({
                "method": method,
                **{key: metrics[method].get(key) for key in fields[1:7]},
                "detector_latency_mean_ms": timing["mean_ms"],
                "detector_latency_p50_ms": timing["p50_ms"],
                "detector_latency_p95_ms": timing["p95_ms"],
            })
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
