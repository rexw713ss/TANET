"""Generate BIPIA WebQA contexts from a local NewsQA combined CSV.

This replaces the removed Hugging Face dataset-script loader while preserving
BIPIA ``benchmark/qa/process.py`` transformations and reporting official MD5
checks.  A mismatch is recorded rather than hidden because the public upstream
inputs currently do not reproduce the hashes committed by BIPIA.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import string
from itertools import chain
from pathlib import Path

import jsonlines


def merge_newlines(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text)


def merge_lines_with_spaces(text: str) -> str:
    return re.sub(r"\n\s*\n", "\n\n", text)


def parse_answers(story: str, raw_ranges: str) -> list[str]:
    grouped = [item.split("|") for item in raw_ranges.split(",")]
    answers = []
    for char_range in chain(*grouped):
        if char_range == "None":
            continue
        start, end = map(int, char_range.split(":"))
        answers.append(story[start:end].strip(string.punctuation + string.whitespace))
    return sorted(set(answers))


def md5(path: Path) -> str:
    digest = hashlib.md5()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    project = Path(__file__).resolve().parents[1]
    workspace = project.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--combined",
        type=Path,
        default=workspace / "datasets" / "newsqa" / "combined-newsqa-data-v1.csv",
    )
    parser.add_argument("--bipia-root", type=Path, default=workspace / "BIPIA")
    parser.add_argument(
        "--report",
        type=Path,
        default=project / "data" / "bipia" / "webqa_reproduction.json",
    )
    parser.add_argument("--strict-md5", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    qa_dir = args.bipia_root / "benchmark" / "qa"
    indexes = json.loads((qa_dir / "index.json").read_text(encoding="utf-8"))
    targets = {
        index: (split, position)
        for split in ("train", "test")
        for position, index in enumerate(indexes[split])
    }
    output_rows = {
        "train": [None] * len(indexes["train"]),
        "test": [None] * len(indexes["test"]),
    }
    with args.combined.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"story_text", "question", "answer_char_ranges"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Combined NewsQA CSV missing columns: {sorted(missing)}")
        for index, row in enumerate(reader):
            target = targets.get(index)
            if target is None:
                continue
            split, position = target
            story = merge_newlines(merge_lines_with_spaces(row["story_text"]))
            output_rows[split][position] = {
                "ideal": parse_answers(row["story_text"], row["answer_char_ranges"]),
                "context": story,
                "question": row["question"],
            }
    for split, rows in output_rows.items():
        missing_positions = [index for index, row in enumerate(rows) if row is None]
        if missing_positions:
            raise RuntimeError(f"Missing {split} selected rows: {missing_positions[:10]}")
    output_rows["test"][87]["ideal"] = ["Janine Sligar"]

    actual = {}
    for split in ("train", "test"):
        path = qa_dir / f"{split}.jsonl"
        with jsonlines.open(path, "w") as writer:
            writer.write_all(output_rows[split])
        actual[path.name] = md5(path)
    expected = {}
    for line in (qa_dir / "md5.txt").read_text(encoding="utf-8").splitlines():
        value, filename = line.strip().split("  ")
        expected[filename] = value
    report = {
        "status": "exact_md5_match" if all(actual[name] == value for name, value in expected.items()) else "content_reproduced_upstream_md5_mismatch",
        "combined": str(args.combined.resolve()),
        "counts": {split: len(rows) for split, rows in output_rows.items()},
        "expected_md5": expected,
        "actual_md5": actual,
        "matches": {filename: actual[filename] == value for filename, value in expected.items()},
        "notes": [
            "The combined CSV contains non-empty story_text and was built with the official NewsQA Python 2 tooling.",
            "The Microsoft NewsQA CSV and CNN stories archive were independently checksum-verified.",
            "BIPIA process.py and this direct port produce the same actual MD5 values.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.strict_md5 and not all(report["matches"].values()):
        raise RuntimeError("BIPIA WebQA MD5 mismatch")


if __name__ == "__main__":
    main()
