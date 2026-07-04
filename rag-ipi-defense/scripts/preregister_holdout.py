"""Pre-register untouched BIPIA test rows after excluding consumed pilot contexts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def stable_rank(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=Path, default=project / "data" / "splits" / "test_sample.jsonl")
    parser.add_argument(
        "--consumed-predictions",
        nargs="+",
        type=Path,
        default=[
            project / "results" / "main-holdout-v4" / "predictions.jsonl",
        ],
    )
    parser.add_argument("--output", type=Path, default=project / "data" / "splits" / "next_holdout_v5.jsonl")
    parser.add_argument(
        "--manifest", type=Path, default=project / "data" / "splits" / "next_holdout_v5_manifest.json"
    )
    parser.add_argument("--seed", type=int, default=20260705)
    parser.add_argument("--contexts-per-task", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pool = read_jsonl(args.pool)
    by_id = {row["id"]: row for row in pool}
    consumed_predictions = []
    for path in args.consumed_predictions:
        consumed_predictions.extend(read_jsonl(path))
    consumed_ids = sorted({row["id"] for row in consumed_predictions})
    consumed_contexts = {
        (by_id[row_id]["task"], by_id[row_id]["context_index"])
        for row_id in consumed_ids
        if row_id in by_id
    }
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in pool:
        key = (row["task"], row["context_index"])
        if key not in consumed_contexts:
            groups[key].append(row)

    selected: list[dict] = []
    selected_contexts = []
    family_counts: dict[str, int] = defaultdict(int)
    position_counts: dict[str, int] = defaultdict(int)
    tasks = sorted({row["task"] for row in pool})
    for task in tasks:
        task_groups = [
            (key, rows)
            for key, rows in groups.items()
            if key[0] == task
            and any(row["label"] == "benign" for row in rows)
            and any(row["label"] == "malicious" for row in rows)
            and any(
                row["label"] == "benign"
                and row.get("reference_answer", "").strip().casefold() != "unknown"
                for row in rows
            )
        ]
        if not task_groups:
            raise RuntimeError(f"No untouched complete context group for task {task}")
        ordered_groups = sorted(
            task_groups,
            key=lambda item: stable_rank(args.seed, f"{item[0][0]}:{item[0][1]}"),
        )
        if len(ordered_groups) < args.contexts_per_task:
            raise RuntimeError(
                f"Task {task} has {len(ordered_groups)} untouched groups, "
                f"needs {args.contexts_per_task}"
            )
        for key, rows in ordered_groups[: args.contexts_per_task]:
            benign = next(
                row for row in rows
                if row["label"] == "benign"
                and row.get("reference_answer", "").strip().casefold() != "unknown"
            )
            malicious = min(
                (row for row in rows if row["label"] == "malicious"),
                key=lambda row: (
                    family_counts[row.get("attack_family", "unknown")],
                    position_counts[row.get("position", "unknown")],
                    stable_rank(args.seed, row["id"]),
                ),
            )
            selected.extend((benign, malicious))
            family = malicious.get("attack_family", "unknown")
            position = malicious.get("position", "unknown")
            family_counts[family] += 1
            position_counts[position] += 1
            selected_contexts.append(
                {
                    "task": task,
                    "context_index": key[1],
                    "attack_family": family,
                    "position": position,
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in selected:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "locked before inference",
        "seed": args.seed,
        "pool": str(args.pool.resolve()),
        "consumed_predictions": [str(path.resolve()) for path in args.consumed_predictions],
        "contexts_per_task": args.contexts_per_task,
        "policy": [
            "Exclude the entire task/context_index group if any row was used in the prior pilot.",
            "Select the requested number of untouched context groups per task by seeded SHA-256 rank.",
            "Select one benign and one malicious row from the same context.",
            "Greedily balance malicious attack family and insertion position; seeded SHA-256 breaks ties.",
            "Exclude unknown-reference benign rows so utility has a meaningful reference.",
        ],
        "consumed_ids": consumed_ids,
        "excluded_context_groups": [
            {"task": task, "context_index": index}
            for task, index in sorted(consumed_contexts)
        ],
        "selected_context_groups": selected_contexts,
        "selected_attack_family_counts": dict(sorted(family_counts.items())),
        "selected_position_counts": dict(sorted(position_counts.items())),
        "selected_ids": [row["id"] for row in selected],
        "output": str(args.output.resolve()),
        "output_sha256": sha256(args.output),
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
