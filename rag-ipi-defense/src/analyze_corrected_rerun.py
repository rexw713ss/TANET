"""Validate and summarize the 2026-07-18 identical-prompt paired rerun."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path

from downstream_rag import paired_comparisons, summarize


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    directory = root / "results" / "rerun-2026-07-18"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v4", type=Path, default=directory / "v4-core-r2" / "predictions.jsonl")
    parser.add_argument("--v5", type=Path, default=directory / "v5-core-r2" / "predictions.jsonl")
    parser.add_argument("--pooled", type=Path, default=directory / "pooled-r2" / "report.json")
    parser.add_argument("--output", type=Path, default=directory / "acceptance-report.json")
    return parser.parse_args()


def validate_reuse(rows: list[dict], methods: tuple[str, ...]) -> dict:
    by_key = {(row["method"], row["id"]): row for row in rows}
    checks = {}
    for method in methods:
        generated = [row for row in rows if row["method"] == method and row["generated"]]
        pairs = [(by_key[("no_defense", row["id"])], row) for row in generated]
        checks[method] = {
            "generated_rows": len(pairs),
            "byte_identical_answers": sum(left["answer"] == right["answer"] for left, right in pairs),
            "reuse_provenance_rows": sum(bool(right.get("generation_reused_from")) for _, right in pairs),
            "malicious_generated_rows": sum(right["label"] == "malicious" for _, right in pairs),
            "identical_attack_labels": sum(
                left.get("attack_success") == right.get("attack_success")
                for left, right in pairs if right["label"] == "malicious"
            ),
        }
        if checks[method]["byte_identical_answers"] != len(pairs):
            raise RuntimeError(f"{method} contains a non-identical reused PASS answer")
        if checks[method]["reuse_provenance_rows"] != len(pairs):
            raise RuntimeError(f"{method} is missing generation reuse provenance")
    return checks


def main() -> None:
    args = parse_args()
    v4 = read_jsonl(args.v4)
    v5 = read_jsonl(args.v5)
    expected_v4 = {"no_defense": 100, "srs_only": 100, "two_stage": 100, "full_tier2": 100}
    expected_v5 = {"no_defense": 100, "two_stage": 100}
    for method, expected in expected_v4.items():
        if sum(row["method"] == method for row in v4) != expected:
            raise RuntimeError(f"v4 {method} row count is not {expected}")
    for method, expected in expected_v5.items():
        if sum(row["method"] == method for row in v5) != expected:
            raise RuntimeError(f"v5 {method} row count is not {expected}")
    accepted = v4 + v5
    errors = [row for row in accepted if row.get("generation_error")]
    missing_asr = [row for row in accepted if row["label"] == "malicious" and row.get("attack_success") is None]
    if errors or missing_asr:
        raise RuntimeError(f"errors={len(errors)}, missing_asr={len(missing_asr)}")
    v4_reuse = validate_reuse(v4, ("srs_only", "two_stage", "full_tier2"))
    v5_reuse = validate_reuse(v5, ("two_stage",))
    v4_metrics = {
        method: summarize([row for row in v4 if row["method"] == method])
        for method in expected_v4
    }
    v4_paired = paired_comparisons(v4)
    full = [row for row in v4 if row["method"] == "full_tier2"]
    routed = [row for row in v4 if row["method"] == "two_stage"]
    report = {
        "status": "accepted",
        "protocol": "identical sample + effective generator prompt reuses one Gemma 4 answer and evaluator result",
        "sources": {
            "v4": {"path": str(args.v4.resolve()), "sha256": sha256(args.v4)},
            "v5": {"path": str(args.v5.resolve()), "sha256": sha256(args.v5)},
            "pooled": {"path": str(args.pooled.resolve()), "sha256": sha256(args.pooled)},
        },
        "row_counts": {"v4": expected_v4, "v5": expected_v5},
        "generation_errors": 0,
        "missing_asr_labels": 0,
        "reuse_checks": {"v4": v4_reuse, "v5": v5_reuse},
        "v4_metrics": v4_metrics,
        "v4_paired_vs_no_defense": v4_paired,
        "candidate_routed_vs_full_tier2": {
            "tier2_call_reduction": 1 - sum(row["tier2_triggered"] for row in routed) / sum(row["tier2_triggered"] for row in full),
            "mean_detector_latency_ms": {
                "candidate_routed": statistics.fmean(row["detector_latency_ms"] for row in routed),
                "full_tier2": statistics.fmean(row["detector_latency_ms"] for row in full),
            },
            "full_to_routed_mean_latency_ratio": (
                statistics.fmean(row["detector_latency_ms"] for row in full)
                / statistics.fmean(row["detector_latency_ms"] for row in routed)
            ),
            "asr": {"candidate_routed": v4_metrics["two_stage"]["attack_success_rate"], "full_tier2": v4_metrics["full_tier2"]["attack_success_rate"]},
            "benign_block_rate": {"candidate_routed": v4_metrics["two_stage"]["benign_block_rate"], "full_tier2": v4_metrics["full_tier2"]["benign_block_rate"]},
            "benign_utility": {"candidate_routed": v4_metrics["two_stage"]["benign_task_utility"], "full_tier2": v4_metrics["full_tier2"]["benign_task_utility"]},
        },
        "human_annotation_scope": "The completed 126-row adjudication applies to legacy v4 outputs, not the fresh rerun outputs.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
