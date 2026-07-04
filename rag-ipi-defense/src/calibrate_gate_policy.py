"""Calibrate candidate-routed Tier-1 gate thresholds on validation only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tier2_mac import has_directive_candidate


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=root / "data" / "splits" / "validation.jsonl")
    parser.add_argument(
        "--features", type=Path, default=root / "results" / "calibration" / "validation_features.jsonl"
    )
    parser.add_argument(
        "--srs-calibration", type=Path, default=root / "results" / "calibration" / "calibration.json"
    )
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "gate-calibration-v2")
    parser.add_argument("--max-malicious-pass", type=float, default=0.02)
    parser.add_argument("--max-benign-block", type=float, default=0.01)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = read_jsonl(args.data)
    features = {row["id"]: row for row in read_jsonl(args.features)}
    srs_calibration = json.loads(args.srs_calibration.read_text(encoding="utf-8"))
    weights = srs_calibration["selected"]["weights"]
    cases = []
    for row in rows:
        feature = features[row["id"]]
        score = sum(weights[name] * feature[f"{signal}_shift" if signal == "intent" else f"{signal}_density" if signal == "instruction" else "pressure_signal"] for name, signal in (("alpha", "intent"), ("beta", "instruction"), ("gamma", "pressure")))
        cases.append(
            {
                "id": row["id"],
                "label": row["label"],
                "score": score,
                "directive_candidate": has_directive_candidate(row["xext"]),
            }
        )
    malicious_n = sum(row["label"] == "malicious" for row in cases)
    benign_n = len(cases) - malicious_n
    thresholds = [index / 200 for index in range(201)]
    candidates = []
    for low in thresholds:
        for high in thresholds:
            if high < low:
                continue
            decisions = []
            for row in cases:
                if row["score"] > high:
                    decision = "BLOCK"
                elif row["directive_candidate"] or row["score"] >= low:
                    decision = "REVIEW"
                else:
                    decision = "PASS"
                decisions.append((row, decision))
            malicious_pass = sum(
                row["label"] == "malicious" and decision == "PASS"
                for row, decision in decisions
            ) / malicious_n
            benign_block = sum(
                row["label"] == "benign" and decision == "BLOCK"
                for row, decision in decisions
            ) / benign_n
            review_rate = sum(decision == "REVIEW" for _, decision in decisions) / len(cases)
            block_rate = sum(decision == "BLOCK" for _, decision in decisions) / len(cases)
            feasible = malicious_pass <= args.max_malicious_pass and benign_block <= args.max_benign_block
            rank = (
                0 if feasible else 1,
                review_rate if feasible else 10 * malicious_pass + 10 * benign_block + review_rate,
                malicious_pass,
                benign_block,
                -block_rate,
            )
            candidates.append(
                (
                    rank,
                    {
                        "tau_low": low,
                        "tau_high": high,
                        "malicious_pass_rate": malicious_pass,
                        "benign_auto_block_rate": benign_block,
                        "review_rate": review_rate,
                        "block_rate": block_rate,
                        "feasible": feasible,
                    },
                )
            )
    selected = min(candidates, key=lambda item: item[0])[1]
    report = {
        "scope": "BIPIA validation only",
        "policy": "BLOCK score>tau_high; REVIEW directive_candidate or score>=tau_low; otherwise PASS",
        "constraints": {
            "max_malicious_pass_rate": args.max_malicious_pass,
            "max_benign_auto_block_rate": args.max_benign_block,
        },
        "weights": weights,
        "selected": selected,
        "candidate_signal": {
            "benign_rate": sum(row["label"] == "benign" and row["directive_candidate"] for row in cases) / benign_n,
            "malicious_rate": sum(row["label"] == "malicious" and row["directive_candidate"] for row in cases) / malicious_n,
        },
        "rows": len(cases),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "calibration.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
