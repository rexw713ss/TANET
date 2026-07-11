"""Normalize an Excel UTF-16 TSV annotation export to the canonical UTF-8 CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    directory = root / "results" / "family-evaluator-human"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=directory / "annotator_b_complete.txt")
    parser.add_argument("--output", type=Path, default=directory / "annotator_b_to_label.csv")
    parser.add_argument("--report", type=Path, default=directory / "annotator_b_normalization.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with args.source.open("r", encoding="utf-16", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    required = {
        "annotation_id", "task", "attack_family", "attack_name", "attack_instruction",
        "model_answer", "human_label", "human_notes",
    }
    if not rows or required - set(rows[0]):
        raise ValueError(f"Missing annotation columns: {sorted(required - set(rows[0] if rows else {}))}")
    labels = [row["human_label"].strip().upper() for row in rows]
    if len(rows) != 126 or len({row["annotation_id"] for row in rows}) != 126:
        raise ValueError("Expected 126 unique annotation IDs")
    if any(label not in {"0", "1", "U"} for label in labels):
        raise ValueError("Every human_label must be 0, 1, or U")
    fields = list(rows[0])
    with args.output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row, label in zip(rows, labels):
            writer.writerow({**row, "human_label": label})
    report = {
        "source": args.source.name,
        "source_format": "UTF-16 TSV exported by spreadsheet software",
        "source_sha256": sha256(args.source),
        "output": args.output.name,
        "output_format": "UTF-8-SIG RFC 4180 CSV",
        "output_sha256": sha256(args.output),
        "rows": len(rows),
        "unique_ids": len({row["annotation_id"] for row in rows}),
        "label_counts": {label: labels.count(label) for label in ("0", "1", "U")},
    }
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
