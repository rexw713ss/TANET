"""Retry only failed family labels in a completed run and recompute summaries atomically."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from downstream_rag import paired_comparisons, summarize
from family_asr import FamilyEvaluatorConfig, evaluate_attack


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--model", default="gemma4:latest")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    predictions_path = args.run_dir / "predictions.jsonl"
    rows = read_jsonl(predictions_path)
    config = FamilyEvaluatorConfig(model=args.model)
    repairs = []
    for row in rows:
        judgement = row.get("attack_judgement")
        if row.get("label") != "malicious" or row.get("attack_success") is not None:
            continue
        if not isinstance(judgement, dict) or "error" not in judgement:
            continue
        result = evaluate_attack(row, row.get("answer", ""), config)
        row["attack_success"] = bool(result["attack_success"])
        row["attack_judgement"] = result
        row["attack_judge_latency_ms"] = float(result.get("latency_ms", 0.0))
        repairs.append({"method": row["method"], "id": row["id"], "previous_error": judgement["error"]})
    if not repairs:
        print("No failed family labels to repair.")
        return
    methods = sorted({row["method"] for row in rows})
    metrics = {method: summarize([row for row in rows if row["method"] == method]) for method in methods}
    baseline_utility = metrics.get("no_defense", {}).get("benign_task_utility")
    for method in methods:
        utility = metrics[method]["benign_task_utility"]
        metrics[method]["utility_preservation"] = utility / baseline_utility if utility is not None and baseline_utility else None
    comparisons = paired_comparisons(rows)
    manifest_path = args.run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.setdefault("post_run_repairs", []).append(
        {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "reason": "retry schema-truncated family evaluator JSON only; generated answers unchanged",
            "model": args.model,
            "repairs": repairs,
        }
    )
    tmp = predictions_path.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(predictions_path)
    (args.run_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.run_dir / "paired_comparisons.json").write_text(json.dumps(comparisons, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    with (args.run_dir / "metrics.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["method", "n", "attack_success_rate", "benign_task_utility", "malicious_task_utility", "utility_preservation", "benign_block_rate", "malicious_block_rate", "tier2_trigger_rate"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for method in methods:
            writer.writerow({"method": method, **{field: metrics[method].get(field) for field in fields[1:]}})
    print(json.dumps({"repairs": repairs, "metrics": metrics}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
