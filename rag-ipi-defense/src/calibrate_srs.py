"""Calibrate semantic SRS weights and gate thresholds on validation only."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from embedding_intent import EmbeddingConfig, EmbeddingIntentScorer
from main_pipeline import average_precision, load_dataset, safe_divide
from srs_score import SRSConfig, compute_srs


def weight_grid(step: int = 10):
    for alpha_i in range(step + 1):
        for beta_i in range(step - alpha_i + 1):
            gamma_i = step - alpha_i - beta_i
            yield alpha_i / step, beta_i / step, gamma_i / step


def candidate_thresholds(step: float = 0.025) -> list[float]:
    count = round(1.0 / step)
    return [round(index * step, 6) for index in range(count + 1)]


def gate_metrics(labels: list[int], scores: list[float], low: float, high: float) -> dict:
    malicious = sum(labels)
    benign = len(labels) - malicious
    malicious_pass = sum(label and score < low for label, score in zip(labels, scores))
    benign_block = sum(not label and score > high for label, score in zip(labels, scores))
    review = sum(low <= score <= high for score in scores)
    auto_block_malicious = sum(label and score > high for label, score in zip(labels, scores))
    low_tp = sum(label and score >= low for label, score in zip(labels, scores))
    low_fp = sum(not label and score >= low for label, score in zip(labels, scores))
    precision = safe_divide(low_tp, low_tp + low_fp)
    recall = safe_divide(low_tp, malicious)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "malicious_pass_rate": safe_divide(malicious_pass, malicious),
        "benign_auto_block_rate": safe_divide(benign_block, benign),
        "review_rate": safe_divide(review, len(labels)),
        "auto_block_malicious_rate": safe_divide(auto_block_malicious, malicious),
        "gate_precision_at_tau_low": precision,
        "gate_recall_at_tau_low": recall,
        "gate_f1_at_tau_low": f1,
    }


def tune(features: list[dict]) -> dict:
    labels = [int(row["label"] == "malicious") for row in features]
    thresholds = candidate_thresholds()
    best = None
    evaluated = 0
    for alpha, beta, gamma in weight_grid():
        scores = [
            alpha * row["intent_shift"]
            + beta * row["instruction_density"]
            + gamma * row["pressure_signal"]
            for row in features
        ]
        ap = average_precision(labels, scores)
        for low in thresholds:
            for high in thresholds:
                if high < low:
                    continue
                metrics = gate_metrics(labels, scores, low, high)
                evaluated += 1
                pass_rate = metrics["malicious_pass_rate"] or 0.0
                block_rate = metrics["benign_auto_block_rate"] or 0.0
                review_rate = metrics["review_rate"] or 0.0
                constraint_penalty = int(pass_rate > 0.05) + int(block_rate > 0.01)
                objective = 8.0 * pass_rate + 12.0 * block_rate + 0.25 * review_rate
                rank = (constraint_penalty, objective, -(ap or 0.0), -alpha, -beta)
                if best is None or rank < best[0]:
                    best = (
                        rank,
                        {
                            "weights": {"alpha": alpha, "beta": beta, "gamma": gamma},
                            "thresholds": {"tau_low": low, "tau_high": high},
                            "metrics": {**metrics, "auprc_average_precision": ap},
                            "objective": objective,
                        },
                    )
    assert best is not None
    selected = best[1]
    weights = selected["weights"]
    scores = [
        weights["alpha"] * row["intent_shift"]
        + weights["beta"] * row["instruction_density"]
        + weights["gamma"] * row["pressure_signal"]
        for row in features
    ]
    benign = len(labels) - sum(labels)
    classification_candidates = []
    for threshold in thresholds:
        tp = sum(label and score >= threshold for label, score in zip(labels, scores))
        fp = sum(not label and score >= threshold for label, score in zip(labels, scores))
        fn = sum(label and score < threshold for label, score in zip(labels, scores))
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else 0.0
        )
        fpr = safe_divide(fp, benign) or 0.0
        classification_candidates.append(
            (
                (int(fpr > 0.05), -f1, -float(recall or 0.0), threshold),
                {
                    "threshold": threshold,
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "false_positive_rate": fpr,
                },
            )
        )
    selected["srs_only"] = min(classification_candidates, key=lambda item: item[0])[1]
    return {**selected, "candidates_evaluated": evaluated}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=root / "data" / "splits" / "validation.jsonl")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "calibration")
    parser.add_argument("--embedding-cache", type=Path, default=root / "data" / "cache" / "embedding.sqlite3")
    parser.add_argument("--embedding-model", default="intfloat/multilingual-e5-small")
    parser.add_argument("--embedding-revision", default="fd1525a9fd15316a2d503bf26ab031a61d056e98")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset = load_dataset([args.data])
    scorer = EmbeddingIntentScorer(
        EmbeddingConfig(
            model_id=args.embedding_model,
            revision=args.embedding_revision,
            cache_path=str(args.embedding_cache),
        )
    )
    base_config = SRSConfig(intent_method=scorer.method)
    features: list[dict] = []
    for index, row in enumerate(dataset, 1):
        record = compute_srs(row["xuser"], row["xext"], base_config, intent_scorer=scorer)
        features.append(
            {
                "id": row["id"],
                "label": row["label"],
                "task": row.get("task"),
                "position": row.get("position"),
                "attack_family": row.get("attack_family"),
                "intent_shift": record["intent_shift"],
                "instruction_density": record["instruction_density"],
                "pressure_signal": record["pressure_signal"],
            }
        )
        if index % 25 == 0 or index == len(dataset):
            print(f"Embedded {index}/{len(dataset)} validation rows", flush=True)
    selected = tune(features)
    config = SRSConfig(
        **selected["weights"],
        **selected["thresholds"],
        intent_method=scorer.method,
    )
    report = {
        "data": str(args.data.resolve()),
        "rows": len(dataset),
        "label_counts": {
            "malicious": sum(row["label"] == "malicious" for row in dataset),
            "benign": sum(row["label"] == "benign" for row in dataset),
        },
        "selection_policy": {
            "sealed_test": "No official BIPIA test row is used.",
            "target_malicious_pass_rate": "<= 0.05 when feasible",
            "target_benign_auto_block_rate": "<= 0.01 when feasible",
            "objective": "8*malicious_pass + 12*benign_auto_block + 0.25*review_rate",
        },
        "embedding": scorer.metadata(),
        "selected": selected,
        "srs_config": asdict(config),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "validation_features.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in features:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (args.output_dir / "calibration.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    scorer.close()


if __name__ == "__main__":
    main()
