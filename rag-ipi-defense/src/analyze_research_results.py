"""Build paper-ready analyses from frozen validation and sealed-test artifacts.

This script is descriptive: it never recalibrates the deployed Gate and never
changes a generated answer or an attack-success judgement.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from main_pipeline import average_precision


ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "results" / "calibration" / "validation_features.jsonl"
MAIN = ROOT / "results" / "main-holdout-v4" / "predictions.jsonl"
EXTERNAL = ROOT / "results" / "external-stability" / "report.json"
EXTERNAL_PREDICTIONS = ROOT / "results" / "external-stability" / "predictions.jsonl"
EXTERNAL_TWO_STAGE = ROOT / "results" / "external-two-stage-sample" / "report.json"
FULL_TIER2 = ROOT / "results" / "full-tier2-baseline" / "comparison_report.json"
SEALED_REPLICATIONS = ROOT / "results" / "sealed-replications-v4-v5" / "report.json"
OUTPUT = ROOT / "results" / "research-synthesis"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    rate = successes / total
    denominator = 1 + z * z / total
    centre = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return [0.0 if lower < 1e-15 else lower, 1.0 if 1 - upper < 1e-15 else upper]


def exact_mcnemar(baseline_only: int, method_only: int) -> float:
    discordant = baseline_only + method_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, value) for value in range(min(baseline_only, method_only) + 1))
    return min(1.0, 2 * tail / (2**discordant))


def operating_point(labels: list[int], scores: list[float], max_fpr: float = 0.01) -> dict:
    """Select a validation-only descriptive point maximizing recall under an FPR cap."""
    candidates = sorted(set(scores))
    best = None
    for threshold in candidates:
        predictions = [score > threshold for score in scores]
        tp = sum(label == 1 and prediction for label, prediction in zip(labels, predictions))
        fp = sum(label == 0 and prediction for label, prediction in zip(labels, predictions))
        fn = sum(label == 1 and not prediction for label, prediction in zip(labels, predictions))
        tn = sum(label == 0 and not prediction for label, prediction in zip(labels, predictions))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        candidate = {
            "threshold": threshold,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fpr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }
        if fpr <= max_fpr and (
            best is None
            or (recall, f1, precision, -threshold)
            > (best["recall"], best["f1"], best["precision"], -best["threshold"])
        ):
            best = candidate
    if best is None:
        raise RuntimeError("No operating point satisfies the FPR constraint")
    return best


def validation_ablation(rows: list[dict]) -> list[dict]:
    labels = [int(row["label"] == "malicious") for row in rows]
    prevalence = sum(labels) / len(labels)
    score_functions = {
        "intent_only": lambda row: row["intent_shift"],
        "instruction_only": lambda row: row["instruction_density"],
        "pressure_only": lambda row: row["pressure_signal"],
        "selected_srs": lambda row: 0.6 * row["intent_shift"] + 0.4 * row["instruction_density"],
    }
    output = []
    for name, function in score_functions.items():
        scores = [float(function(row)) for row in rows]
        point = operating_point(labels, scores)
        ap = average_precision(labels, scores)
        output.append({
            "feature_set": name,
            "n": len(rows),
            "malicious_prevalence": prevalence,
            "auprc_average_precision": ap,
            "auprc_lift_over_prevalence": ap / prevalence if ap is not None else None,
            "operating_point_rule": "maximize recall subject to validation FPR <= 1%; block when score > threshold",
            **point,
        })
    return output


def malicious_subgroups(rows: list[dict], dimension: str) -> list[dict]:
    output = []
    methods = ("no_defense", "boundary_reminder", "srs_only", "two_stage")
    values = sorted({row[dimension] for row in rows if row["label"] == "malicious"})
    for value in values:
        for method in methods:
            selected = [
                row for row in rows
                if row["label"] == "malicious" and row[dimension] == value and row["method"] == method
            ]
            successes = sum(row["attack_success"] is True for row in selected)
            interval = wilson(successes, len(selected))
            output.append({
                "dimension": dimension,
                "group": value,
                "method": method,
                "n": len(selected),
                "attack_successes": successes,
                "attack_success_rate": successes / len(selected),
                "asr_ci95_low": interval[0],
                "asr_ci95_high": interval[1],
                "block_rate": sum(row["decision"] == "BLOCK" for row in selected) / len(selected),
                "tier2_trigger_rate": sum(bool(row["tier2_triggered"]) for row in selected) / len(selected),
            })
    return output


def paired_subgroup_effects(rows: list[dict], dimension: str) -> list[dict]:
    malicious = [row for row in rows if row["label"] == "malicious"]
    values = sorted({row[dimension] for row in malicious})
    by_method = defaultdict(dict)
    for row in malicious:
        by_method[row["method"]][row["id"]] = row
    output = []
    for value in values:
        baseline = {
            identifier: row for identifier, row in by_method["no_defense"].items() if row[dimension] == value
        }
        for method in ("boundary_reminder", "srs_only", "two_stage"):
            identifiers = sorted(set(baseline) & set(by_method[method]))
            pairs = [(baseline[identifier], by_method[method][identifier]) for identifier in identifiers]
            baseline_only = sum(a["attack_success"] is True and b["attack_success"] is not True for a, b in pairs)
            method_only = sum(a["attack_success"] is not True and b["attack_success"] is True for a, b in pairs)
            difference = statistics.fmean(
                int(b["attack_success"] is True) - int(a["attack_success"] is True) for a, b in pairs
            )
            output.append({
                "dimension": dimension,
                "group": value,
                "method": method,
                "paired_n": len(pairs),
                "asr_difference_vs_no_defense": difference,
                "baseline_only_success": baseline_only,
                "method_only_success": method_only,
                "exact_mcnemar_p": exact_mcnemar(baseline_only, method_only),
            })
    return output


def benign_task_utility(rows: list[dict]) -> list[dict]:
    output = []
    for task in sorted({row["task"] for row in rows}):
        for method in ("no_defense", "boundary_reminder", "srs_only", "two_stage"):
            selected = [
                row for row in rows if row["label"] == "benign" and row["task"] == task and row["method"] == method
            ]
            output.append({
                "task": task,
                "method": method,
                "n": len(selected),
                "mean_task_utility": statistics.fmean(float(row["task_utility"]) for row in selected),
                "block_rate": sum(row["decision"] == "BLOCK" for row in selected) / len(selected),
                "tier2_trigger_rate": sum(bool(row["tier2_triggered"]) for row in selected) / len(selected),
            })
    return output


def latency_summary(rows: list[dict]) -> list[dict]:
    output = []
    for method in ("no_defense", "boundary_reminder", "srs_only", "two_stage"):
        selected = [row for row in rows if row["method"] == method]
        values = sorted(float(row["detector_latency_ms"]) for row in selected)
        for quantile, label in ((0.5, "p50"), (0.95, "p95")):
            position = (len(values) - 1) * quantile
            lower = math.floor(position)
            upper = math.ceil(position)
            value = values[lower] if lower == upper else values[lower] + (values[upper] - values[lower]) * (position - lower)
            if label == "p50":
                p50 = value
            else:
                p95 = value
        output.append({
            "method": method,
            "n": len(selected),
            "detector_latency_mean_ms": statistics.fmean(values),
            "detector_latency_p50_ms": p50,
            "detector_latency_p95_ms": p95,
        })
    return output


def injecagent_attack_classes(rows: list[dict]) -> list[dict]:
    output = []
    malicious = [row for row in rows if row["source"] == "InjecAgent" and row["label"] == "malicious"]
    for suite in ("base", "enhanced"):
        for attack_class in ("direct_harm", "data_stealing"):
            selected = [
                row for row in malicious if row["suite"] == suite and row["attack_class"] == attack_class
            ]
            passes = sum(row["decision"] == "PASS" for row in selected)
            interval = wilson(passes, len(selected))
            output.append({
                "suite": suite,
                "attack_class": attack_class,
                "n": len(selected),
                "pass_rate": passes / len(selected),
                "pass_rate_ci95_low": interval[0],
                "pass_rate_ci95_high": interval[1],
                "review_rate": sum(row["decision"] == "REVIEW" for row in selected) / len(selected),
                "block_rate": sum(row["decision"] == "BLOCK" for row in selected) / len(selected),
            })
    return output


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    validation = read_jsonl(VALIDATION)
    main_rows = read_jsonl(MAIN)
    external = json.loads(EXTERNAL.read_text(encoding="utf-8"))
    external_predictions = read_jsonl(EXTERNAL_PREDICTIONS)
    external_two_stage = json.loads(EXTERNAL_TWO_STAGE.read_text(encoding="utf-8"))
    full_tier2 = json.loads(FULL_TIER2.read_text(encoding="utf-8"))
    sealed_replications = json.loads(SEALED_REPLICATIONS.read_text(encoding="utf-8"))
    ablation = validation_ablation(validation)
    subgroup_rows = malicious_subgroups(main_rows, "task") + malicious_subgroups(main_rows, "position")
    paired_rows = paired_subgroup_effects(main_rows, "task") + paired_subgroup_effects(main_rows, "position")
    utility_rows = benign_task_utility(main_rows)
    latency_rows = latency_summary(main_rows)
    injecagent_rows = injecagent_attack_classes(external_predictions)
    report = {
        "scope": "Paper-ready synthesis of frozen artifacts; validation ablation is descriptive; sealed test is not recalibrated.",
        "inputs": {
            "validation_features": "results/calibration/validation_features.jsonl",
            "main_predictions": "results/main-holdout-v4/predictions.jsonl",
            "external_report": "results/external-stability/report.json",
            "external_predictions": "results/external-stability/predictions.jsonl",
            "external_two_stage": "results/external-two-stage-sample/report.json",
            "full_tier2_baseline": "results/full-tier2-baseline/comparison_report.json",
            "sealed_replications": "results/sealed-replications-v4-v5/report.json",
        },
        "validation_ablation": ablation,
        "headline_effect": {
            "no_defense_asr": 0.24,
            "two_stage_asr": 0.02,
            "absolute_risk_reduction": 0.22,
            "relative_asr_reduction": (0.24 - 0.02) / 0.24,
            "paired_difference_ci95": [-0.34, -0.12],
            "exact_mcnemar_p": 0.0009765625,
        },
        "external_generalization": {
            "injecagent_base_pass_rate": external["injecagent_suites"]["base"]["pass_rate"],
            "injecagent_enhanced_block_rate": external["injecagent_suites"]["enhanced"]["block_rate"],
            "injecagent_pair_decision_agreement": external["injecagent_pair_stability"]["decision_agreement"],
            "houyi_seed_pass_rate": external["overall"]["HouYi"]["malicious"]["pass_rate"],
            "houyi_all_variants_intercepted_rate": external["houyi_seed_stability"]["all_15_variants_intercepted_rate"],
            "injecagent_by_attack_class": injecagent_rows,
            "preregistered_two_stage_sample": {
                "rows": external_two_stage["rows"],
                "injecagent_base_pass_rate": external_two_stage["injecagent_by_suite"]["base"]["pass_rate"],
                "injecagent_enhanced_pass_rate": external_two_stage["injecagent_by_suite"]["enhanced"]["pass_rate"],
                "houyi_pass_rate": external_two_stage["overall"]["HouYi"]["malicious"]["pass_rate"],
            },
        },
        "full_tier2_baseline": {
            "attack_success_rate": full_tier2["metrics"]["full_tier2"]["attack_success_rate"],
            "utility_preservation": full_tier2["metrics"]["full_tier2"]["utility_preservation"],
            "benign_block_rate": full_tier2["metrics"]["full_tier2"]["benign_block_rate"],
            "tier2_call_reduction_from_routing": full_tier2["routing_cost"]["tier2_call_reduction"],
            "mean_detector_latency_ratio_full_over_routed": full_tier2["routing_cost"]["mean_detector_latency_ratio_full_over_routed"],
        },
        "sealed_replication_summary": {
            "replications": ["v4", "v5"],
            "pooled_rows": sealed_replications["pooled"]["no_defense"]["n"],
            "pooled_no_defense_asr": sealed_replications["pooled"]["no_defense"]["attack_success_rate"],
            "pooled_two_stage_asr": sealed_replications["pooled"]["two_stage"]["attack_success_rate"],
            "pooled_paired_difference": sealed_replications["pooled_paired"]["attack_success_rate_difference"],
            "pooled_paired_difference_ci95": sealed_replications["pooled_paired"]["attack_success_rate_difference_ci95"],
            "pooled_mcnemar_p": sealed_replications["pooled_paired"]["mcnemar"]["exact_two_sided_p"],
            "pooled_utility_preservation": sealed_replications["pooled"]["two_stage"]["utility_preservation"],
        },
        "interpretation_guardrails": [
            "External PASS is a Tier-1 detector escape proxy, not downstream agent ASR.",
            "Subgroup estimates are exploratory and small; no multiplicity-adjusted significance claim is made.",
            "Validation ablation supports feature design but is not an independent test-set comparison.",
        ],
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_csv(OUTPUT / "validation_ablation.csv", ablation)
    write_csv(OUTPUT / "malicious_subgroups.csv", subgroup_rows)
    write_csv(OUTPUT / "paired_subgroup_effects.csv", paired_rows)
    write_csv(OUTPUT / "benign_utility_by_task.csv", utility_rows)
    write_csv(OUTPUT / "detector_latency.csv", latency_rows)
    write_csv(OUTPUT / "injecagent_attack_classes.csv", injecagent_rows)
    (OUTPUT / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
