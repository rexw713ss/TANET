"""Create leakage-resistant BIPIA calibration and downstream-test samples.

The official BIPIA test contexts/templates are never used for calibration.
Within the official train side, both context IDs and attack variants are
assigned to disjoint fit/validation groups.  Only same-group combinations are
materialized, so neither a context nor an attack template crosses the split.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from import_bipia import (  # noqa: E402
    INSERT_FUNCTIONS,
    context_text,
    flatten_attacks,
    read_jsonl,
    reference_answer,
    user_task,
)


TASKS = ("email", "table", "code", "qa", "abstract")
POSITIONS = ("start", "middle", "end")


def stable_rank(value: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def split_context_indexes(count: int, task: str, seed: int, validation_fraction: float) -> tuple[list[int], list[int]]:
    indexes = sorted(range(count), key=lambda i: stable_rank(f"{task}:context:{i}", seed))
    validation_count = max(1, round(count * validation_fraction))
    return sorted(indexes[validation_count:]), sorted(indexes[:validation_count])


def split_attacks(attacks: list[dict], task: str, seed: int) -> tuple[list[dict], list[dict]]:
    """Hold out one variant per attack family for validation."""
    families: dict[str, list[dict]] = defaultdict(list)
    for attack in attacks:
        families[attack["attack_family"]].append(attack)
    fit: list[dict] = []
    validation: list[dict] = []
    for family, variants in sorted(families.items()):
        ordered = sorted(
            variants,
            key=lambda row: stable_rank(f"{task}:attack:{family}:{row['attack_variant']}", seed),
        )
        validation.append(ordered[0])
        fit.extend(ordered[1:])
    return fit, validation


def limited(values: list, maximum: int | None, seed: int, namespace: str) -> list:
    if maximum is None or len(values) <= maximum:
        return list(values)
    return sorted(values, key=lambda value: stable_rank(f"{namespace}:{value}", seed))[:maximum]


def choose_attack_position_pairs(
    attacks: list[dict], count: int, context_key: str, seed: int
) -> list[tuple[dict, str]]:
    candidates = [(attack, position) for position in POSITIONS for attack in attacks]
    random.Random(f"{seed}:{context_key}").shuffle(candidates)
    if count <= 0 or count >= len(candidates):
        return candidates
    # Cover positions before filling additional slots.
    selected: list[tuple[dict, str]] = []
    for position in POSITIONS:
        match = next(pair for pair in candidates if pair[1] == position and pair not in selected)
        selected.append(match)
        if len(selected) == count:
            return selected
    selected.extend(pair for pair in candidates if pair not in selected)
    return selected[:count]


def materialize(
    *,
    bipia_root: Path,
    raw_split: str,
    logical_split: str,
    context_assignments: dict[str, list[int]],
    attack_assignments: dict[str, list[dict]],
    output_path: Path,
    seed: int,
    max_contexts_per_task: int | None,
    malicious_per_context: int,
) -> dict:
    counts: Counter[str] = Counter()
    group_fingerprints = {"contexts": set(), "attacks": set()}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for task in TASKS:
            raw_path = bipia_root / "benchmark" / task / f"{raw_split}.jsonl"
            contexts = read_jsonl(raw_path)
            context_indexes = limited(
                context_assignments[task], max_contexts_per_task, seed, f"{logical_split}:{task}:context"
            )
            attacks = attack_assignments[task]
            for context_index in context_indexes:
                sample = contexts[context_index]
                clean = context_text(task, sample)
                common = {
                    "source": "BIPIA",
                    "task": task,
                    "split": logical_split,
                    "raw_split": raw_split,
                    "context_index": context_index,
                    "xuser": user_task(task, sample),
                    "reference_answer": reference_answer(sample),
                    "context_file": str(raw_path.relative_to(bipia_root)).replace("\\", "/"),
                }
                benign = {
                    "id": f"bipia-{task}-{logical_split}-b-{context_index:04d}",
                    "label": "benign",
                    "xext": clean,
                    "position": "none",
                    **common,
                }
                handle.write(json.dumps(benign, ensure_ascii=False) + "\n")
                counts[f"{task}.benign"] += 1
                group_fingerprints["contexts"].add(f"{task}:{context_index}")

                pairs = choose_attack_position_pairs(
                    attacks, malicious_per_context, f"{logical_split}:{task}:{context_index}", seed
                )
                for attack, position in pairs:
                    malicious = {
                        "id": (
                            f"bipia-{task}-{logical_split}-m-{position}-"
                            f"{context_index:04d}-{attack['attack_variant']:03d}-"
                            f"{stable_rank(attack['attack_name'], seed)[:6]}"
                        ),
                        "label": "malicious",
                        "xext": INSERT_FUNCTIONS[position](clean, attack["attack_str"], seed),
                        "position": position,
                        **attack,
                        **common,
                    }
                    handle.write(json.dumps(malicious, ensure_ascii=False) + "\n")
                    counts[f"{task}.malicious"] += 1
                    group_fingerprints["attacks"].add(f"{task}:{attack['attack_name']}")
    return {
        "file": str(output_path),
        "counts": dict(sorted(counts.items())),
        "rows": sum(counts.values()),
        "context_groups": sorted(group_fingerprints["contexts"]),
        "attack_groups": sorted(group_fingerprints["attacks"]),
        "sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
    }


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bipia-root", type=Path, default=project_root.parent / "BIPIA")
    parser.add_argument("--output-dir", type=Path, default=project_root / "data" / "splits")
    parser.add_argument("--seed", type=int, default=2023)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    parser.add_argument("--fit-contexts-per-task", type=int, default=50)
    parser.add_argument("--validation-contexts-per-task", type=int, default=25)
    parser.add_argument("--test-contexts-per-task", type=int, default=3)
    parser.add_argument("--malicious-per-context", type=int, default=3)
    parser.add_argument("--test-malicious-per-context", type=int, default=15)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0 < args.validation_fraction < 1:
        raise ValueError("--validation-fraction must be between 0 and 1")
    bipia_root = args.bipia_root.resolve()
    output_dir = args.output_dir.resolve()
    fit_contexts: dict[str, list[int]] = {}
    validation_contexts: dict[str, list[int]] = {}
    fit_attacks: dict[str, list[dict]] = {}
    validation_attacks: dict[str, list[dict]] = {}
    test_contexts: dict[str, list[int]] = {}
    test_attacks: dict[str, list[dict]] = {}

    for task in TASKS:
        train_rows = read_jsonl(bipia_root / "benchmark" / task / "train.jsonl")
        fit_contexts[task], validation_contexts[task] = split_context_indexes(
            len(train_rows), task, args.seed, args.validation_fraction
        )
        attack_kind = "code" if task == "code" else "text"
        train_attack_rows = flatten_attacks(
            bipia_root / "benchmark" / f"{attack_kind}_attack_train.json"
        )
        fit_attacks[task], validation_attacks[task] = split_attacks(
            train_attack_rows, task, args.seed
        )
        test_rows = read_jsonl(bipia_root / "benchmark" / task / "test.jsonl")
        test_contexts[task] = list(range(len(test_rows)))
        test_attacks[task] = flatten_attacks(
            bipia_root / "benchmark" / f"{attack_kind}_attack_test.json"
        )

    outputs = {
        "fit": materialize(
            bipia_root=bipia_root,
            raw_split="train",
            logical_split="fit",
            context_assignments=fit_contexts,
            attack_assignments=fit_attacks,
            output_path=output_dir / "fit.jsonl",
            seed=args.seed,
            max_contexts_per_task=args.fit_contexts_per_task,
            malicious_per_context=args.malicious_per_context,
        ),
        "validation": materialize(
            bipia_root=bipia_root,
            raw_split="train",
            logical_split="validation",
            context_assignments=validation_contexts,
            attack_assignments=validation_attacks,
            output_path=output_dir / "validation.jsonl",
            seed=args.seed,
            max_contexts_per_task=args.validation_contexts_per_task,
            malicious_per_context=args.malicious_per_context,
        ),
        "test_sample": materialize(
            bipia_root=bipia_root,
            raw_split="test",
            logical_split="test",
            context_assignments=test_contexts,
            attack_assignments=test_attacks,
            output_path=output_dir / "test_sample.jsonl",
            seed=args.seed,
            max_contexts_per_task=args.test_contexts_per_task,
            malicious_per_context=args.test_malicious_per_context,
        ),
    }
    fit_context_set = set(outputs["fit"]["context_groups"])
    validation_context_set = set(outputs["validation"]["context_groups"])
    fit_attack_set = set(outputs["fit"]["attack_groups"])
    validation_attack_set = set(outputs["validation"]["attack_groups"])
    leakage_checks = {
        "fit_validation_context_overlap": sorted(fit_context_set & validation_context_set),
        "fit_validation_attack_overlap": sorted(fit_attack_set & validation_attack_set),
        "official_test_uses_distinct_raw_context_and_attack_files": True,
    }
    if leakage_checks["fit_validation_context_overlap"] or leakage_checks["fit_validation_attack_overlap"]:
        raise RuntimeError(f"Split leakage detected: {leakage_checks}")
    manifest = {
        "schema": "BIPIA leakage-resistant split v1",
        "seed": args.seed,
        "validation_fraction": args.validation_fraction,
        "sampling": {
            "fit_contexts_per_task": args.fit_contexts_per_task,
            "validation_contexts_per_task": args.validation_contexts_per_task,
            "test_contexts_per_task": args.test_contexts_per_task,
            "malicious_per_context": args.malicious_per_context,
            "test_malicious_per_context": args.test_malicious_per_context,
        },
        "policy": [
            "Official BIPIA test contexts and test attack templates are sealed from calibration.",
            "Fit and validation use disjoint official-train context IDs.",
            "Fit and validation hold out attack variants within every attack family.",
            "Only within-split context/template combinations are materialized.",
        ],
        "leakage_checks": leakage_checks,
        "outputs": outputs,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
