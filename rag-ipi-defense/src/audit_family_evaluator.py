"""Audit family ASR labels with a larger independent local judge and export disagreements."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from downstream_rag import wilson_ci
from family_asr import FamilyEvaluatorConfig, MODEL_EVALUATED_FAMILIES, evaluate_attack


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def cohen_kappa(left: list[bool], right: list[bool]) -> float | None:
    if not left or len(left) != len(right):
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_positive = sum(left) / len(left)
    right_positive = sum(right) / len(right)
    expected = left_positive * right_positive + (1 - left_positive) * (1 - right_positive)
    return (observed - expected) / (1 - expected) if expected < 1 else 1.0


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, default=root / "results" / "main-holdout-v4" / "predictions.jsonl")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "family-evaluator-audit")
    parser.add_argument("--independent-model", default="gemma4:31b")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = [
        row for row in read_jsonl(args.predictions)
        if row["label"] == "malicious"
        and row.get("generated")
        and row.get("attack_success") is not None
    ]
    config = FamilyEvaluatorConfig(model=args.independent_model, seed=1729)
    audited = []
    for index, row in enumerate(rows, 1):
        family = row.get("attack_family")
        primary = bool(row["attack_success"])
        if family in MODEL_EVALUATED_FAMILIES:
            independent_result = evaluate_attack(row, row["answer"], config)
            independent = bool(independent_result["attack_success"])
            independence = "larger_local_model"
        else:
            independent_result = evaluate_attack(row, row["answer"], config)
            independent = bool(independent_result["attack_success"])
            independence = "deterministic_replay"
        audited.append(
            {
                "method": row["method"],
                "id": row["id"],
                "task": row.get("task"),
                "attack_family": family,
                "attack_name": row.get("attack_name"),
                "answer": row["answer"],
                "primary_label": primary,
                "independent_label": independent,
                "agreement": primary == independent,
                "audit_type": independence,
                "independent_result": independent_result,
            }
        )
        print(f"Audited {index}/{len(rows)} {row['method']} {row['id']}", flush=True)
    groups = defaultdict(list)
    for row in audited:
        groups[row["audit_type"]].append(row)

    def metrics(group: list[dict]) -> dict:
        agreements = sum(row["agreement"] for row in group)
        left = [row["primary_label"] for row in group]
        right = [row["independent_label"] for row in group]
        return {
            "n": len(group),
            "agreement": agreements / len(group) if group else None,
            "agreement_wilson_ci95": wilson_ci(agreements, len(group)),
            "cohen_kappa": cohen_kappa(left, right),
            "primary_positive": sum(left),
            "independent_positive": sum(right),
            "disagreements": len(group) - agreements,
        }

    report = {
        "predictions": str(args.predictions.resolve()),
        "primary_model": "recorded in each prediction's attack_judgement",
        "independent_model": args.independent_model,
        "independent_seed": config.seed,
        "limitations": [
            "Model agreement is not a substitute for human ground truth.",
            "Deterministic families are replayed for implementation consistency, not independently judged.",
            "The blinded CSV leaves human_label empty for a future human reliability estimate.",
        ],
        "overall": metrics(audited),
        "by_audit_type": {name: metrics(group) for name, group in sorted(groups.items())},
        "family_counts": dict(sorted(Counter(row["attack_family"] for row in audited).items())),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "audit.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in audited:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    with (args.output_dir / "human_annotation_packet.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["id", "method", "task", "attack_family", "attack_name", "answer", "human_label", "human_notes"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in audited:
            writer.writerow({field: row.get(field, "") for field in fields})
    (args.output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
