"""Validate two human packets and report agreement, kappa, AC1, and conflicts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def cohen_kappa(left: list[str], right: list[str]) -> float | None:
    if not left or len(left) != len(right):
        return None
    categories = sorted(set(left) | set(right))
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    expected = sum(
        (left.count(category) / len(left)) * (right.count(category) / len(right))
        for category in categories
    )
    return (observed - expected) / (1 - expected) if expected < 1 else 1.0


def gwet_ac1(left: list[str], right: list[str]) -> float | None:
    if not left or len(left) != len(right):
        return None
    categories = sorted(set(left) | set(right))
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    marginals = [
        (left.count(category) + right.count(category)) / (2 * len(left))
        for category in categories
    ]
    expected = (
        sum(probability * (1 - probability) for probability in marginals) / (len(categories) - 1)
        if len(categories) > 1 else 0.0
    )
    return (observed - expected) / (1 - expected) if expected < 1 else 1.0


def agreement(left: list[str], right: list[str]) -> dict:
    return {
        "n": len(left),
        "raw_agreement": sum(a == b for a, b in zip(left, right)) / len(left) if left else None,
        "cohen_kappa": cohen_kappa(left, right),
        "gwet_ac1": gwet_ac1(left, right),
        "left_counts": dict(sorted(Counter(left).items())),
        "right_counts": dict(sorted(Counter(right).items())),
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    directory = root / "results" / "family-evaluator-human"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--annotator-a", type=Path, default=directory / "annotator_a_completed.csv")
    parser.add_argument("--annotator-b", type=Path, default=directory / "annotator_b_to_label.csv")
    parser.add_argument("--key", type=Path, default=directory / "annotation_key.csv")
    parser.add_argument("--audit", type=Path, default=root / "results" / "family-evaluator-audit" / "audit.jsonl")
    parser.add_argument("--output-dir", type=Path, default=directory)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    a = {row["annotation_id"]: row for row in read_csv(args.annotator_a)}
    b = {row["annotation_id"]: row for row in read_csv(args.annotator_b)}
    if set(a) != set(b):
        raise ValueError("Annotator packets do not contain identical annotation IDs")
    valid = {"0", "1", "U"}
    completed = []
    incomplete = []
    for annotation_id in sorted(a):
        left = a[annotation_id]["human_label"].strip().upper()
        right = b[annotation_id]["human_label"].strip().upper()
        if left not in valid or right not in valid:
            incomplete.append(annotation_id)
        else:
            completed.append((annotation_id, left, right))
    conflict_path = args.output_dir / "adjudication_conflicts.csv"
    existing_adjudication = {
        row["annotation_id"]: row for row in read_csv(conflict_path)
    } if conflict_path.exists() else {}
    report = {
        "status": "complete" if not incomplete else "awaiting_annotator_b",
        "expected_rows": len(a),
        "completed_pairs": len(completed),
        "incomplete_pairs": len(incomplete),
        "three_class": agreement([x[1] for x in completed], [x[2] for x in completed]),
    }
    binary = [item for item in completed if item[1] in {"0", "1"} and item[2] in {"0", "1"}]
    report["binary_resolved_subset"] = agreement([x[1] for x in binary], [x[2] for x in binary])
    report["binary_resolved_subset"]["excluded_uncertain_pairs"] = len(completed) - len(binary)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    conflicts = [
        {
            "annotation_id": annotation_id,
            "annotator_a_label": left,
            "annotator_b_label": right,
            "adjudicated_label": existing_adjudication.get(annotation_id, {}).get("adjudicated_label", ""),
            "adjudication_notes": existing_adjudication.get(annotation_id, {}).get("adjudication_notes", ""),
        }
        for annotation_id, left, right in completed if left != right
    ]
    with conflict_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["annotation_id", "annotator_a_label", "annotator_b_label", "adjudicated_label", "adjudication_notes"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(conflicts)
    key = {row["annotation_id"]: row for row in read_csv(args.key)}
    audit_rows = [json.loads(line) for line in args.audit.read_text(encoding="utf-8").splitlines() if line.strip()]
    audit = {(row["method"], row["id"]): row for row in audit_rows}
    consensus = []
    for annotation_id, left, right in completed:
        human = left if left == right and left in {"0", "1"} else ""
        if not human:
            human = existing_adjudication.get(annotation_id, {}).get("adjudicated_label", "").strip()
        if human not in {"0", "1"}:
            continue
        mapping = key[annotation_id]
        evaluator = audit[(mapping["method"], mapping["sample_id"])]
        consensus.append({
            "annotation_id": annotation_id,
            "method": mapping["method"],
            "human": human,
            "primary": "1" if evaluator["primary_label"] else "0",
            "independent": "1" if evaluator["independent_label"] else "0",
        })
    report["human_consensus"] = {
        "resolved_n": len(consensus),
        "unresolved_n": len(a) - len(consensus),
        "positive_rate": sum(row["human"] == "1" for row in consensus) / len(consensus) if consensus else None,
        "vs_primary_evaluator": agreement(
            [row["human"] for row in consensus], [row["primary"] for row in consensus]
        ),
        "vs_independent_evaluator": agreement(
            [row["human"] for row in consensus], [row["independent"] for row in consensus]
        ),
        "asr_by_method": {
            method: {
                "n": sum(row["method"] == method for row in consensus),
                "human_attack_success_rate": (
                    sum(row["method"] == method and row["human"] == "1" for row in consensus)
                    / sum(row["method"] == method for row in consensus)
                    if any(row["method"] == method for row in consensus) else None
                ),
            }
            for method in sorted({row["method"] for row in consensus})
        },
    }
    (args.output_dir / "agreement_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
