"""Compare Tier-2 prompts on validation hard negatives/positives only."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from pathlib import Path

from embedding_intent import EmbeddingConfig, EmbeddingIntentScorer
from main_pipeline import load_dataset, safe_divide
from srs_score import SRSConfig, compute_srs
from tier2_mac import (
    ADJUDICATOR_PROMPT,
    ADJUDICATOR_PROMPT_V2,
    ADJUDICATOR_PROMPT_V3,
    AdjudicatorError,
    OllamaConfig,
    structured_adjudication,
)


PROMPTS = {
    "v1": {"text": ADJUDICATOR_PROMPT, "candidate_spans": False},
    "v2": {"text": ADJUDICATOR_PROMPT_V2, "candidate_spans": False},
    "v3": {"text": ADJUDICATOR_PROMPT_V3, "candidate_spans": True},
}


def select_hard_cases(rows: list[dict], per_label_task: int) -> list[dict]:
    selected: list[dict] = []
    tasks = sorted({row["task"] for row in rows})
    for task in tasks:
        for label in ("benign", "malicious"):
            candidates = [
                row for row in rows
                if row["task"] == task
                and row["label"] == label
                and row["srs"]["tier1_decision"] == "REVIEW"
            ]
            # High-score benign rows are hard negatives; low-score malicious
            # rows are hard positives for the adjudicator.
            candidates.sort(
                key=lambda row: row["srs"]["srs"],
                reverse=(label == "benign"),
            )
            selected.extend(candidates[:per_label_task])
    return selected


def metrics(predictions: list[dict]) -> dict:
    tp = sum(row["label"] == "malicious" and row["predicted_label"] == "malicious" for row in predictions)
    tn = sum(row["label"] == "benign" and row["predicted_label"] == "benign" for row in predictions)
    fp = sum(row["label"] == "benign" and row["predicted_label"] != "benign" for row in predictions)
    fn = sum(row["label"] == "malicious" and row["predicted_label"] != "malicious" for row in predictions)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "n": len(predictions),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": safe_divide(fp, fp + tn),
        "accuracy": safe_divide(tp + tn, len(predictions)),
        "error_count": sum(row["error"] is not None for row in predictions),
        "mean_latency_ms": statistics.fmean(row["latency_ms"] for row in predictions),
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=root / "data" / "splits" / "validation.jsonl")
    parser.add_argument("--calibration", type=Path, default=root / "results" / "calibration" / "calibration.json")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "tier2-validation-v3")
    parser.add_argument("--embedding-cache", type=Path, default=root / "data" / "cache" / "embedding.sqlite3")
    parser.add_argument("--per-label-task", type=int, default=3)
    parser.add_argument("--model", default="gemma4:latest")
    parser.add_argument("--tau-judge", type=float, default=0.70)
    parser.add_argument("--prompts", default="v3")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    prompt_names = [name.strip() for name in args.prompts.split(",") if name.strip()]
    unknown = set(prompt_names) - set(PROMPTS)
    if unknown:
        raise ValueError(f"Unknown prompts: {sorted(unknown)}")
    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    embedding = calibration["embedding"]
    scorer = EmbeddingIntentScorer(
        EmbeddingConfig(
            model_id=embedding["model_id"],
            revision=embedding["revision"],
            onnx_filename=embedding["onnx_filename"],
            max_length=embedding["max_length"],
            max_chunk_chars=embedding["max_chunk_chars"],
            cache_path=str(args.embedding_cache),
        )
    )
    config = SRSConfig(**calibration["srs_config"])
    rows = load_dataset([args.data])
    enriched = []
    for row in rows:
        enriched.append({**row, "srs": compute_srs(row["xuser"], row["xext"], config, intent_scorer=scorer)})
    selected = select_hard_cases(enriched, args.per_label_task)
    expected = len({row["task"] for row in rows}) * 2 * args.per_label_task
    if len(selected) != expected:
        raise RuntimeError(f"Expected {expected} selected rows, got {len(selected)}")

    ollama = OllamaConfig.from_env(args.model)
    predictions: list[dict] = []
    for prompt_name in prompt_names:
        for index, row in enumerate(selected, 1):
            print(f"[{prompt_name}] {index}/{len(selected)} {row['id']}", flush=True)
            started = time.perf_counter_ns()
            error = None
            try:
                result = structured_adjudication(
                    row["xuser"],
                    row["xext"],
                    row["srs"],
                    ollama,
                    args.tau_judge,
                    system_prompt=PROMPTS[prompt_name]["text"],
                    include_candidate_spans=PROMPTS[prompt_name]["candidate_spans"],
                )
                predicted = result["risk_label"]
            except AdjudicatorError as exc:
                # Match deployed fail-closed behavior: an invalid/error result
                # blocks and therefore counts as malicious for FPR/recall.
                error = str(exc)
                result = None
                predicted = "malicious"
            latency_ms = (time.perf_counter_ns() - started) / 1_000_000
            predictions.append(
                {
                    "prompt": prompt_name,
                    "id": row["id"],
                    "task": row["task"],
                    "label": row["label"],
                    "srs": row["srs"],
                    "predicted_label": predicted,
                    "result": result,
                    "error": error,
                    "latency_ms": round(latency_ms, 6),
                }
            )
    report = {
        name: metrics([row for row in predictions if row["prompt"] == name])
        for name in prompt_names
    }
    manifest = {
        "scope": "validation only; no official BIPIA test row",
        "data": str(args.data.resolve()),
        "selection": "highest-score benign and lowest-score malicious REVIEW row per task",
        "per_label_task": args.per_label_task,
        "selected_ids": [row["id"] for row in selected],
        "model": args.model,
        "tau_judge": args.tau_judge,
        "prompt_hashes": {
            name: hashlib.sha256(PROMPTS[name]["text"].encode("utf-8")).hexdigest()
            for name in prompt_names
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (args.output_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (args.output_dir / "metrics.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    scorer.close()


if __name__ == "__main__":
    main()
