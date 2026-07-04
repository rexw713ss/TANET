"""Build a validation-only Gate safety--cost Pareto curve."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from downstream_rag import wilson_ci
from tier2_mac import has_directive_candidate


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def pareto_front(rows: list[dict]) -> list[dict]:
    """Minimize residual attack pass, benign block, and Tier-2 review rate."""
    unique = {}
    for row in rows:
        key = (
            row["estimated_malicious_pass_rate"],
            row["estimated_benign_block_rate"],
            row["review_rate"],
        )
        incumbent = unique.get(key)
        if incumbent is None or (row["tau_low"], row["tau_high"]) < (incumbent["tau_low"], incumbent["tau_high"]):
            unique[key] = row
    rows = list(unique.values())
    front = []
    for candidate in rows:
        dominated = any(
            other is not candidate
            and other["estimated_malicious_pass_rate"] <= candidate["estimated_malicious_pass_rate"]
            and other["estimated_benign_block_rate"] <= candidate["estimated_benign_block_rate"]
            and other["review_rate"] <= candidate["review_rate"]
            and (
                other["estimated_malicious_pass_rate"] < candidate["estimated_malicious_pass_rate"]
                or other["estimated_benign_block_rate"] < candidate["estimated_benign_block_rate"]
                or other["review_rate"] < candidate["review_rate"]
            )
            for other in rows
        )
        if not dominated:
            front.append(candidate)
    return sorted(front, key=lambda row: (row["review_rate"], row["estimated_malicious_pass_rate"]))


def svg_curve(rows: list[dict], path: Path) -> None:
    width, height, margin = 760, 480, 65
    plot_w, plot_h = width - 2 * margin, height - 2 * margin
    points = " ".join(
        f"{margin + row['review_rate'] * plot_w:.2f},{height - margin - row['estimated_malicious_pass_rate'] * plot_h:.2f}"
        for row in rows
    )
    circles = "\n".join(
        f'<circle cx="{margin + row["review_rate"] * plot_w:.2f}" cy="{height - margin - row["estimated_malicious_pass_rate"] * plot_h:.2f}" r="3" />'
        for row in rows
    )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="white"/>
<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="black"/>
<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="black"/>
<polyline points="{points}" fill="none" stroke="#1769aa" stroke-width="2"/>
<g fill="#d1495b">{circles}</g>
<text x="{width/2}" y="{height-15}" text-anchor="middle" font-family="sans-serif">Tier-2 review rate (cost)</text>
<text x="18" y="{height/2}" text-anchor="middle" transform="rotate(-90 18 {height/2})" font-family="sans-serif">Estimated malicious pass rate (risk)</text>
<text x="{width/2}" y="30" text-anchor="middle" font-family="sans-serif" font-size="18">Validation-only Gate safety–cost Pareto frontier</text>
</svg>'''
    path.write_text(svg, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=root / "data" / "splits" / "validation.jsonl")
    parser.add_argument("--features", type=Path, default=root / "results" / "calibration" / "validation_features.jsonl")
    parser.add_argument("--calibration", type=Path, default=root / "results" / "calibration" / "calibration.json")
    parser.add_argument("--tier2-metrics", type=Path, default=root / "results" / "tier2-validation-v3" / "metrics.json")
    parser.add_argument("--output-dir", type=Path, default=root / "results" / "gate-safety-cost")
    parser.add_argument("--threshold-step", type=float, default=0.01)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data = read_jsonl(args.data)
    features = {row["id"]: row for row in read_jsonl(args.features)}
    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    tier2 = json.loads(args.tier2_metrics.read_text(encoding="utf-8"))["v3"]
    weights = calibration["selected"]["weights"]
    cases = []
    for row in data:
        feature = features[row["id"]]
        score = (
            weights["alpha"] * feature["intent_shift"]
            + weights["beta"] * feature["instruction_density"]
            + weights["gamma"] * feature["pressure_signal"]
        )
        cases.append({**row, "score": score, "directive_candidate": has_directive_candidate(row["xext"])})
    malicious_n = sum(row["label"] == "malicious" for row in cases)
    benign_n = len(cases) - malicious_n
    tier2_positive_n = tier2["tp"] + tier2["fn"]
    tier2_negative_n = tier2["tn"] + tier2["fp"]
    tier2_fnr = tier2["fn"] / tier2_positive_n if tier2_positive_n else 0.0
    tier2_fpr = tier2["fp"] / tier2_negative_n if tier2_negative_n else 0.0
    tier2_fnr_upper = wilson_ci(tier2["fn"], tier2_positive_n)[1] if tier2_positive_n else 1.0
    thresholds = [round(i * args.threshold_step, 6) for i in range(round(1 / args.threshold_step) + 1)]
    candidates = []
    for low in thresholds:
        for high in thresholds:
            if high < low:
                continue
            direct_malicious_pass = malicious_review = benign_review = benign_auto_block = review = 0
            for row in cases:
                if row["score"] > high:
                    decision = "BLOCK"
                elif row["directive_candidate"] or row["score"] >= low:
                    decision = "REVIEW"
                else:
                    decision = "PASS"
                review += decision == "REVIEW"
                if row["label"] == "malicious":
                    direct_malicious_pass += decision == "PASS"
                    malicious_review += decision == "REVIEW"
                else:
                    benign_auto_block += decision == "BLOCK"
                    benign_review += decision == "REVIEW"
            estimated_pass = (direct_malicious_pass + malicious_review * tier2_fnr) / malicious_n
            conservative_pass = (direct_malicious_pass + malicious_review * tier2_fnr_upper) / malicious_n
            estimated_benign_block = (benign_auto_block + benign_review * tier2_fpr) / benign_n
            review_rate = review / len(cases)
            candidates.append(
                {
                    "tau_low": low,
                    "tau_high": high,
                    "estimated_malicious_pass_rate": estimated_pass,
                    "conservative_malicious_pass_rate": conservative_pass,
                    "estimated_benign_block_rate": estimated_benign_block,
                    "review_rate": review_rate,
                    "estimated_tier2_latency_ms_per_request": review_rate * tier2["mean_latency_ms"],
                }
            )
    front = pareto_front(candidates)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(front[0])
    with (args.output_dir / "pareto_frontier.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(front)
    report = {
        "scope": "validation only; no official test outcome used for selection",
        "rows": len(cases),
        "threshold_candidates": len(candidates),
        "pareto_points": len(front),
        "tier2_observed": {
            "false_negative_rate": tier2_fnr,
            "false_negative_rate_wilson_upper95": tier2_fnr_upper,
            "false_positive_rate": tier2_fpr,
            "mean_latency_ms": tier2["mean_latency_ms"],
        },
        "frontier": front,
    }
    (args.output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    svg_curve(front, args.output_dir / "pareto_frontier.svg")
    print(json.dumps({key: value for key, value in report.items() if key != "frontier"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
