"""Combine context-disjoint v4/v5 replications without recalibrating the Gate."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from downstream_rag import paired_comparisons, summarize


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v4", type=Path, default=root / "results" / "main-holdout-v4" / "predictions.jsonl")
    parser.add_argument("--v5", type=Path, default=root / "results" / "main-holdout-v5" / "predictions.jsonl")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "sealed-replications-v4-v5")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sources = {
        "v4": args.v4,
        "v5": args.v5,
    }
    per_replication = {}
    raw_by_replication = {}
    combined = []
    for replication, path in sources.items():
        rows = [row for row in read_jsonl(path) if row["method"] in {"no_defense", "two_stage"}]
        if len(rows) != 200:
            raise RuntimeError(f"{replication} must contain 100 rows for each core method")
        raw_by_replication[replication] = rows
        per_replication[replication] = {
            method: summarize([row for row in rows if row["method"] == method])
            for method in ("no_defense", "two_stage")
        }
        per_replication[replication]["paired"] = paired_comparisons(rows)["two_stage"]
        combined.extend({**row, "replication": replication, "task": f"{replication}:{row['task']}"} for row in rows)
    pooled = {
        method: summarize([row for row in combined if row["method"] == method])
        for method in ("no_defense", "two_stage")
    }
    baseline_utility = pooled["no_defense"]["benign_task_utility"]
    for method in pooled:
        pooled[method]["utility_preservation"] = pooled[method]["benign_task_utility"] / baseline_utility
    pooled_paired = paired_comparisons(combined)["two_stage"]
    report = {
        "scope": "Two independently frozen, context-disjoint BIPIA holdouts; fixed Gate and model settings; no pooled recalibration.",
        "replications": per_replication,
        "pooled": pooled,
        "pooled_paired": pooled_paired,
        "consistency": {
            "v4_asr_difference": per_replication["v4"]["paired"]["attack_success_rate_difference"],
            "v5_asr_difference": per_replication["v5"]["paired"]["attack_success_rate_difference"],
            "same_direction": (
                per_replication["v4"]["paired"]["attack_success_rate_difference"] < 0
                and per_replication["v5"]["paired"]["attack_success_rate_difference"] < 0
            ),
        },
        "statistical_note": "Pooled bootstrap strata are replication x task; exact McNemar uses all 100 paired malicious IDs.",
    }
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    with (output / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "replication", "method", "n", "attack_success_rate", "benign_task_utility",
            "utility_preservation", "benign_block_rate", "malicious_block_rate", "tier2_trigger_rate",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for replication in ("v4", "v5"):
            baseline = per_replication[replication]["no_defense"]["benign_task_utility"]
            for method in ("no_defense", "two_stage"):
                metrics = per_replication[replication][method]
                writer.writerow({
                    "replication": replication,
                    "method": method,
                    **{key: metrics.get(key) for key in fields[2:] if key != "utility_preservation"},
                    "utility_preservation": metrics["benign_task_utility"] / baseline,
                })
        for method in ("no_defense", "two_stage"):
            writer.writerow({"replication": "pooled", "method": method, **{key: pooled[method].get(key) for key in fields[2:]}})
    task_rows = []
    for replication in ("v4", "v5", "pooled"):
        rows = (
            raw_by_replication[replication]
            if replication != "pooled"
            else raw_by_replication["v4"] + raw_by_replication["v5"]
        )
        for task in ("abstract", "code", "email", "qa", "table"):
            for method in ("no_defense", "two_stage"):
                malicious = [row for row in rows if row["task"] == task and row["method"] == method and row["label"] == "malicious"]
                benign = [row for row in rows if row["task"] == task and row["method"] == method and row["label"] == "benign"]
                task_rows.append({
                    "replication": replication,
                    "task": task,
                    "method": method,
                    "malicious_n": len(malicious),
                    "attack_success_rate": sum(row["attack_success"] is True for row in malicious) / len(malicious),
                    "benign_n": len(benign),
                    "benign_task_utility": sum(float(row["task_utility"]) for row in benign) / len(benign),
                    "benign_block_rate": sum(row["decision"] == "BLOCK" for row in benign) / len(benign),
                    "tier2_trigger_rate": sum(row["tier2_triggered"] for row in malicious + benign) / (len(malicious) + len(benign)),
                })
    with (output / "per_task_exploratory.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(task_rows[0]))
        writer.writeheader()
        writer.writerows(task_rows)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
