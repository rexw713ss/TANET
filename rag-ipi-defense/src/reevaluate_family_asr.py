"""Re-evaluate saved downstream answers with BIPIA family-specific evaluators."""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from family_asr import (
    FamilyEvaluationError,
    FamilyEvaluatorConfig,
    evaluate_attack,
    evaluator_metadata,
)


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def bootstrap_ci(values: list[float], seed: int = 20260704, repetitions: int = 5000) -> list[float] | None:
    if not values:
        return None
    rng = random.Random(seed)
    means = sorted(
        sum(rng.choice(values) for _ in values) / len(values)
        for _ in range(repetitions)
    )
    return [means[int(0.025 * (repetitions - 1))], means[int(0.975 * (repetitions - 1))]]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--data", nargs="+", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "family-asr")
    parser.add_argument("--model", default="gemma4:latest")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_rows = {}
    for path in args.data:
        source_rows.update({row["id"]: row for row in read_jsonl(path)})
    predictions = [
        row for row in read_jsonl(args.predictions) if row["label"] == "malicious"
    ]
    config = FamilyEvaluatorConfig(model=args.model)
    cache: dict[tuple[str, str], dict] = {}
    evaluated = []
    for index, row in enumerate(predictions, 1):
        print(f"{index}/{len(predictions)} {row['method']} {row['id']}", flush=True)
        item = source_rows[row["id"]]
        key = (row["id"], row.get("answer", ""))
        error = None
        if key not in cache:
            try:
                cache[key] = evaluate_attack(item, row.get("answer", ""), config)
            except FamilyEvaluationError as exc:
                error = str(exc)
                cache[key] = {
                    "attack_success": None,
                    "confidence": 0.0,
                    "evaluator": "error",
                    "latency_ms": 0.0,
                    "error": error,
                }
        result = cache[key]
        evaluated.append(
            {
                "method": row["method"],
                "id": row["id"],
                "task": item.get("task"),
                "attack_name": item.get("attack_name"),
                "attack_family": item.get("attack_family"),
                "attack_success": result["attack_success"],
                "evaluation": result,
            }
        )

    report = {}
    for method in sorted({row["method"] for row in evaluated}):
        method_rows = [row for row in evaluated if row["method"] == method]
        valid = [row for row in method_rows if row["attack_success"] is not None]
        values = [float(row["attack_success"]) for row in valid]
        families = defaultdict(list)
        for row in valid:
            families[row["attack_family"]].append(float(row["attack_success"]))
        report[method] = {
            "n": len(method_rows),
            "valid_n": len(valid),
            "error_count": len(method_rows) - len(valid),
            "attack_success_rate": sum(values) / len(values) if values else None,
            "attack_success_rate_ci95": bootstrap_ci(values),
            "per_family": {
                family: {"n": len(items), "asr": sum(items) / len(items)}
                for family, items in sorted(families.items())
            },
        }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in evaluated:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (args.output_dir / "metrics.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (args.output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "predictions": str(args.predictions.resolve()),
                "data": [str(path.resolve()) for path in args.data],
                "evaluator": evaluator_metadata(config),
                "bootstrap": {"seed": 20260704, "repetitions": 5000, "level": 0.95},
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
