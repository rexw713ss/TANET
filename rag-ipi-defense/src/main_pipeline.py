"""Reproducible experiment harness aligned with the research proposal."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from srs_score import SRSConfig, compute_srs
from tier2_mac import (
    ADJUDICATOR_PROMPT,
    OUTPUT_SCHEMA,
    AdjudicatorError,
    OllamaConfig,
    structured_adjudication,
)


SUPPORTED_METHODS = {
    "no_defense",
    "keyword",
    "srs_only",
    "two_stage",
    "single_agent",
    "ablation_intent",
    "ablation_instruction",
    "ablation_pressure",
    "ablation_all",
}


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            missing = {"id", "label", "xuser", "xext"} - set(row)
            if missing:
                raise ValueError(f"{path}:{line_number} missing fields {sorted(missing)}")
            if row["label"] not in {"benign", "malicious"}:
                raise ValueError(f"{path}:{line_number} has invalid label {row['label']!r}")
            rows.append(row)
    return rows


def load_dataset(paths: Iterable[Path]) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for path in paths:
        for row in load_jsonl(path):
            if row["id"] in seen:
                raise ValueError(f"Duplicate sample id: {row['id']}")
            seen.add(row["id"])
            row = {**row, "dataset_file": path.name, "source": row.get("source", "local_smoke")}
            rows.append(row)
    if not rows:
        raise ValueError("Dataset is empty")
    return rows


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def average_precision(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    if positives == 0:
        return None
    ranked = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)
    true_positives = 0
    seen = 0
    area = 0.0
    index = 0
    # Evaluate at score thresholds, not arbitrary ordering within tied scores.
    while index < len(ranked):
        score = ranked[index][0]
        group_positives = 0
        group_size = 0
        while index < len(ranked) and ranked[index][0] == score:
            group_positives += ranked[index][1]
            group_size += 1
            index += 1
        true_positives += group_positives
        seen += group_size
        recall_increment = group_positives / positives
        area += (true_positives / seen) * recall_increment
    return min(max(area, 0.0), 1.0)


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def compute_metrics(predictions: list[dict]) -> dict:
    tp = sum(row["label"] == "malicious" and row["decision"] == "BLOCK" for row in predictions)
    tn = sum(row["label"] == "benign" and row["decision"] == "PASS" for row in predictions)
    fp = sum(row["label"] == "benign" and row["decision"] == "BLOCK" for row in predictions)
    fn = sum(row["label"] == "malicious" and row["decision"] == "PASS" for row in predictions)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    labels = [int(row["label"] == "malicious") for row in predictions]
    scores = [float(row["risk_score"]) for row in predictions]
    total_latency = [float(row["total_latency_ms"]) for row in predictions]
    tier1_latency = [float(row["tier1_latency_ms"]) for row in predictions]
    tier2_latency = [float(row["tier2_latency_ms"]) for row in predictions if row["tier2_triggered"]]
    trigger_count = sum(bool(row["tier2_triggered"]) for row in predictions)

    return {
        "n": len(predictions),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auprc_average_precision": average_precision(labels, scores),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "detection_escape_rate_proxy": safe_divide(fn, fn + tp),
        "attack_success_rate": None,
        "utility_preservation": None,
        "tier2_trigger_rate": safe_divide(trigger_count, len(predictions)),
        "latency_ms": {
            "p50_total": percentile(total_latency, 0.50),
            "p95_total": percentile(total_latency, 0.95),
            "p50_tier1": percentile(tier1_latency, 0.50),
            "p95_tier1": percentile(tier1_latency, 0.95),
            "p50_tier2_when_triggered": percentile(tier2_latency, 0.50),
            "p95_tier2_when_triggered": percentile(tier2_latency, 0.95),
        },
        "metric_notes": {
            "detection_escape_rate_proxy": "Malicious detector false-negative rate; not downstream RAG ASR.",
            "attack_success_rate": "Requires a target RAG model and task-specific attack-success evaluator.",
            "utility_preservation": "Requires reference answers or a task-quality evaluator.",
        },
    }


def _adjudicate(
    item: dict,
    srs: dict,
    ollama_config: OllamaConfig,
    tau_judge: float,
    on_judge_error: str,
) -> tuple[dict, float]:
    started = time.perf_counter_ns()
    try:
        result = structured_adjudication(item["xuser"], item["xext"], srs, ollama_config, tau_judge)
    except AdjudicatorError as exc:
        result = {
            "risk_label": "uncertain",
            "risk_type": "none",
            "evidence_span": "",
            "confidence": 0.0,
            "short_reason": "local adjudicator error",
            "decision": on_judge_error.upper(),
            "model": ollama_config.model,
            "tau_judge": tau_judge,
            "error": str(exc),
        }
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    return result, latency_ms


def adjudication_risk_score(adjudication: dict) -> float:
    """Map label confidence to malicious risk without misusing uncertainty confidence."""
    if adjudication["risk_label"] == "malicious":
        return float(adjudication["confidence"])
    if adjudication["risk_label"] == "benign":
        return 1.0 - float(adjudication["confidence"])
    return 0.5


def run_method(
    method: str,
    dataset: list[dict],
    srs_config: SRSConfig,
    ollama_config: OllamaConfig,
    tau_judge: float,
    on_judge_error: str,
    judge_cache: dict[str, tuple[dict, float]],
) -> list[dict]:
    enabled = {
        "ablation_intent": ("intent",),
        "ablation_instruction": ("instruction",),
        "ablation_pressure": ("pressure",),
        "ablation_all": ("intent", "instruction", "pressure"),
    }.get(method, ("intent", "instruction", "pressure"))
    predictions: list[dict] = []

    for item in dataset:
        total_started = time.perf_counter_ns()
        tier1_started = time.perf_counter_ns()
        srs = compute_srs(item["xuser"], item["xext"], srs_config, enabled)
        tier1_latency_ms = (time.perf_counter_ns() - tier1_started) / 1_000_000
        adjudication = None
        tier2_latency_ms = 0.0
        tier2_triggered = False

        if method == "no_defense":
            decision, risk_score = "PASS", 0.0
        elif method == "keyword":
            risk_score = srs["instruction_density"]
            decision = "BLOCK" if risk_score > 0 else "PASS"
        elif method in {"srs_only", "ablation_intent", "ablation_instruction", "ablation_pressure", "ablation_all"}:
            risk_score = srs["srs"]
            decision = "BLOCK" if risk_score >= srs_config.tau_low else "PASS"
        elif method == "two_stage":
            risk_score = srs["srs"]
            if srs["tier1_decision"] == "REVIEW":
                tier2_triggered = True
                if item["id"] not in judge_cache:
                    judge_cache[item["id"]] = _adjudicate(
                        item, srs, ollama_config, tau_judge, on_judge_error
                    )
                adjudication, tier2_latency_ms = judge_cache[item["id"]]
                decision = adjudication["decision"]
                risk_score = adjudication_risk_score(adjudication)
            else:
                decision = srs["tier1_decision"]
        elif method == "single_agent":
            tier2_triggered = True
            cache_key = f"single:{item['id']}"
            if cache_key not in judge_cache:
                judge_cache[cache_key] = _adjudicate(
                    item, srs, ollama_config, tau_judge, on_judge_error
                )
            adjudication, tier2_latency_ms = judge_cache[cache_key]
            decision = adjudication["decision"]
            risk_score = adjudication_risk_score(adjudication)
        else:
            raise ValueError(f"Unsupported method: {method}")

        total_latency_ms = (time.perf_counter_ns() - total_started) / 1_000_000
        predictions.append(
            {
                "method": method,
                "id": item["id"],
                "source": item["source"],
                "dataset_file": item["dataset_file"],
                "label": item["label"],
                "decision": decision,
                "risk_score": round(float(risk_score), 6),
                "tier1": srs,
                "tier2_triggered": tier2_triggered,
                "adjudication": adjudication,
                "tier1_latency_ms": round(tier1_latency_ms, 6),
                "tier2_latency_ms": round(tier2_latency_ms, 6),
                "total_latency_ms": round(total_latency_ms, 6),
            }
        )
    return predictions


def write_results(output_dir: Path, manifest: dict, predictions: list[dict], metrics: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (output_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (output_dir / "metrics.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "method", "n", "tp", "tn", "fp", "fn", "detection_escape_rate_proxy",
            "false_positive_rate", "precision", "recall", "f1", "auprc_average_precision",
            "tier2_trigger_rate", "p50_total_ms", "p95_total_ms",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for method, values in metrics.items():
            writer.writerow(
                {
                    "method": method,
                    **{key: values.get(key) for key in fields if key not in {"method", "p50_total_ms", "p95_total_ms"}},
                    "p50_total_ms": values["latency_ms"]["p50_total"],
                    "p95_total_ms": values["latency_ms"]["p95_total"],
                }
            )


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data",
        nargs="+",
        type=Path,
        default=[base_dir / "data" / "malicious.jsonl", base_dir / "data" / "benign.jsonl"],
    )
    parser.add_argument(
        "--methods",
        default="no_defense,keyword,srs_only,two_stage,ablation_intent,ablation_instruction,ablation_pressure,ablation_all",
        help=f"Comma-separated methods: {','.join(sorted(SUPPORTED_METHODS))}",
    )
    parser.add_argument("--output-dir", type=Path, default=base_dir / "results" / "latest")
    parser.add_argument("--tau-low", type=float, default=0.30)
    parser.add_argument("--tau-high", type=float, default=0.70)
    parser.add_argument("--tau-judge", type=float, default=0.70)
    parser.add_argument("--alpha", type=float, default=0.15)
    parser.add_argument("--beta", type=float, default=0.70)
    parser.add_argument("--gamma", type=float, default=0.15)
    parser.add_argument("--model", default=None)
    parser.add_argument("--on-judge-error", choices=("block", "pass"), default="block")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    methods = [method.strip() for method in args.methods.split(",") if method.strip()]
    unknown = set(methods) - SUPPORTED_METHODS
    if unknown:
        raise ValueError(f"Unsupported methods: {sorted(unknown)}")
    srs_config = SRSConfig(
        alpha=args.alpha,
        beta=args.beta,
        gamma=args.gamma,
        tau_low=args.tau_low,
        tau_high=args.tau_high,
    )
    srs_config.validate()
    ollama_config = OllamaConfig.from_env(args.model)
    dataset = load_dataset(args.data)
    judge_cache: dict[str, tuple[dict, float]] = {}
    all_predictions: list[dict] = []
    all_metrics: dict[str, dict] = {}

    for method in methods:
        print(f"Running {method} on {len(dataset)} samples...", flush=True)
        predictions = run_method(
            method,
            dataset,
            srs_config,
            ollama_config,
            args.tau_judge,
            args.on_judge_error,
            judge_cache,
        )
        all_predictions.extend(predictions)
        all_metrics[method] = compute_metrics(predictions)

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "data_paths": [str(path.resolve()) for path in args.data],
        "dataset_size": len(dataset),
        "dataset_sources": sorted({row["source"] for row in dataset}),
        "methods": methods,
        "srs_config": asdict(srs_config),
        "ollama_config": asdict(ollama_config),
        "tier2_protocol": {
            "prompt_sha256": hashlib.sha256(ADJUDICATOR_PROMPT.encode("utf-8")).hexdigest(),
            "schema_sha256": hashlib.sha256(
                json.dumps(OUTPUT_SCHEMA, sort_keys=True).encode("utf-8")
            ).hexdigest(),
        },
        "tau_judge": args.tau_judge,
        "on_judge_error": args.on_judge_error,
        "limitations": [
            "local_smoke data are not BIPIA and cannot support benchmark claims",
            "intent_shift uses a lexical Jaccard proxy because no embedding model is configured",
            "attack_success_rate and utility_preservation require a downstream RAG task harness",
        ],
    }
    write_results(args.output_dir, manifest, all_predictions, all_metrics)
    print(json.dumps(all_metrics, ensure_ascii=False, indent=2))
    print(f"Results written to {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
