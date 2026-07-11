"""Freeze a balanced InjecAgent/HouYi sample before running Tier-2."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    directory = root / "data" / "external_stability"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injecagent", type=Path, default=directory / "injecagent.jsonl")
    parser.add_argument("--houyi", type=Path, default=directory / "houyi_seed.jsonl")
    parser.add_argument("--output", type=Path, default=directory / "two_stage_sample.jsonl")
    parser.add_argument("--manifest", type=Path, default=directory / "two_stage_sample_manifest.json")
    parser.add_argument("--seed", type=int, default=20260711)
    return parser.parse_args()


def sample_groups(rows: list[dict], group_keys: tuple[str, ...], per_group: int, rng: random.Random) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(str(row.get(key, "")) for key in group_keys)].append(row)
    selected = []
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda row: row["id"])
        if len(group) < per_group:
            raise ValueError(f"Group {key} has only {len(group)} rows; need {per_group}")
        selected.extend(rng.sample(group, per_group))
    return selected


def main() -> None:
    args = parse_args()
    if args.manifest.exists():
        raise FileExistsError(f"Manifest already frozen: {args.manifest}")
    rng = random.Random(args.seed)
    injec = read_jsonl(args.injecagent)
    houyi = read_jsonl(args.houyi)
    selected = sample_groups(
        [row for row in injec if row["label"] == "malicious"],
        ("suite", "attack_class"),
        10,
        rng,
    )
    selected += rng.sample(sorted([row for row in injec if row["label"] == "benign"], key=lambda row: row["id"]), 10)
    selected += sample_groups(
        [row for row in houyi if row["label"] == "malicious"],
        ("separator", "attack_family"),
        2,
        rng,
    )
    selected += rng.sample(sorted([row for row in houyi if row["label"] == "benign"], key=lambda row: row["id"]), 10)
    selected = sorted(selected, key=lambda row: row["id"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in selected:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    counts = Counter(f"{row['source']}.{row['suite']}.{row['label']}" for row in selected)
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "frozen_before_tier2_execution",
        "seed": args.seed,
        "selection": {
            "InjecAgent malicious": "10 per suite x attack_class (2 x 2 x 10 = 40)",
            "InjecAgent benign": "10 of 17 clean controls",
            "HouYi malicious": "2 per separator x intention (5 x 5 x 2 = 50)",
            "HouYi benign": "10 of 17 clean controls",
        },
        "rows": len(selected),
        "counts": dict(sorted(counts.items())),
        "source_sha256": {"injecagent": sha256(args.injecagent), "houyi": sha256(args.houyi)},
        "sample_sha256": sha256(args.output),
        "selected_ids": [row["id"] for row in selected],
        "claim_boundary": "Complete two-stage Gate decisions only; no downstream agent action or ASR claim.",
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
