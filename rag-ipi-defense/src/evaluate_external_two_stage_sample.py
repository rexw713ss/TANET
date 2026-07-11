"""Run the frozen candidate-routed two-stage Gate on a preregistered external sample."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from collections import Counter
from pathlib import Path

from embedding_intent import EmbeddingConfig, EmbeddingIntentScorer
from srs_score import SRSConfig, compute_srs
from tier2_mac import ADJUDICATOR_PROMPT_V3, AdjudicatorError, OllamaConfig, has_directive_candidate, structured_adjudication


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_checkpoint(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    temporary.replace(path)


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    rate = successes / total
    denominator = 1 + z * z / total
    centre = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    lower, upper = max(0.0, centre - margin), min(1.0, centre + margin)
    return [0.0 if lower < 1e-15 else lower, 1.0 if 1 - upper < 1e-15 else upper]


def summarize(rows: list[dict]) -> dict:
    decisions = Counter(row["final_decision"] for row in rows)
    passes = decisions["PASS"]
    triggers = sum(row["tier2_triggered"] for row in rows)
    return {
        "n": len(rows),
        "pass_rate": passes / len(rows),
        "pass_rate_ci95": wilson(passes, len(rows)),
        "block_rate": decisions["BLOCK"] / len(rows),
        "tier2_trigger_rate": triggers / len(rows),
        "detector_latency_mean_ms": statistics.fmean(row["detector_latency_ms"] for row in rows),
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=root / "data" / "external_stability" / "two_stage_sample.jsonl")
    parser.add_argument("--sample-manifest", type=Path, default=root / "data" / "external_stability" / "two_stage_sample_manifest.json")
    parser.add_argument("--calibration", type=Path, default=root / "results" / "calibration" / "calibration.json")
    parser.add_argument("--gate-calibration", type=Path, default=root / "results" / "gate-calibration-v2" / "calibration.json")
    parser.add_argument("--embedding-cache", type=Path, default=root / "data" / "cache" / "embedding.sqlite3")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "external-two-stage-sample")
    parser.add_argument("--model", default="gemma4:latest")
    parser.add_argument("--tau-judge", type=float, default=0.70)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sample_manifest = json.loads(args.sample_manifest.read_text(encoding="utf-8"))
    if sample_manifest["status"] != "frozen_before_tier2_execution":
        raise ValueError("External sample was not frozen before execution")
    data = read_jsonl(args.data)
    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    gate = json.loads(args.gate_calibration.read_text(encoding="utf-8"))
    config = SRSConfig(**calibration["srs_config"])
    embedding = calibration["embedding"]
    scorer = EmbeddingIntentScorer(EmbeddingConfig(
        model_id=embedding["model_id"], revision=embedding["revision"],
        onnx_filename=embedding["onnx_filename"], max_length=embedding["max_length"],
        max_chunk_chars=embedding["max_chunk_chars"], cache_path=str(args.embedding_cache),
    ))
    judge = OllamaConfig.from_env(args.model)
    low = float(gate["selected"]["tau_low"])
    high = float(gate["selected"]["tau_high"])
    checkpoint = args.output_dir / "predictions.jsonl"
    predictions = read_jsonl(checkpoint) if args.resume and checkpoint.exists() else []
    completed = {row["id"] for row in predictions}
    for index, row in enumerate(data, 1):
        if row["id"] in completed:
            print(f"{index}/{len(data)} {row['id']} (cached)", flush=True)
            continue
        started = time.perf_counter_ns()
        srs = compute_srs(row["xuser"], row["xext"], config, intent_scorer=scorer)
        candidate = has_directive_candidate(row["xext"])
        if srs["srs"] > high:
            tier1_decision = "BLOCK"
        elif candidate or srs["srs"] >= low:
            tier1_decision = "REVIEW"
        else:
            tier1_decision = "PASS"
        final_decision = tier1_decision
        adjudication = None
        if tier1_decision == "REVIEW":
            try:
                adjudication = structured_adjudication(
                    row["xuser"], row["xext"], {**srs, "directive_candidate_signal": candidate},
                    judge, args.tau_judge, system_prompt=ADJUDICATOR_PROMPT_V3,
                    include_candidate_spans=True,
                )
                final_decision = adjudication["decision"]
            except AdjudicatorError as exc:
                final_decision = "BLOCK"
                adjudication = {"error": str(exc), "decision": "BLOCK"}
        predictions.append({
            "id": row["id"], "source": row["source"], "suite": row["suite"],
            "label": row["label"], "attack_class": row.get("attack_class"),
            "attack_family": row.get("attack_family"), "separator": row.get("separator"),
            "tier1_decision": tier1_decision, "final_decision": final_decision,
            "tier2_triggered": tier1_decision == "REVIEW", "directive_candidate": candidate,
            "srs": srs["srs"], "tier2": adjudication,
            "detector_latency_ms": (time.perf_counter_ns() - started) / 1_000_000,
        })
        completed.add(row["id"])
        write_checkpoint(checkpoint, predictions)
        print(f"{index}/{len(data)} {row['id']} {tier1_decision}->{final_decision}", flush=True)
    report = {
        "scope": "Preregistered external full two-stage Gate; final PASS is still not downstream ASR.",
        "sample_manifest": "data/external_stability/two_stage_sample_manifest.json",
        "rows": len(predictions),
        "gate": {"tau_low": low, "tau_high": high, "policy": "candidate_routed_v2"},
        "model": args.model,
        "overall": {
            source: {
                label: summarize([row for row in predictions if row["source"] == source and row["label"] == label])
                for label in ("malicious", "benign")
            }
            for source in ("InjecAgent", "HouYi")
        },
        "injecagent_by_suite": {
            suite: summarize([
                row for row in predictions
                if row["source"] == "InjecAgent" and row["label"] == "malicious" and row["suite"] == suite
            ])
            for suite in ("base", "enhanced")
        },
        "houyi_by_separator": {
            separator: summarize([
                row for row in predictions
                if row["source"] == "HouYi" and row["label"] == "malicious" and row["separator"] == separator
            ])
            for separator in ("additional", "ignoring", "language", "reasoning", "syntax")
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_checkpoint(checkpoint, predictions)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    scorer.close()


if __name__ == "__main__":
    main()
