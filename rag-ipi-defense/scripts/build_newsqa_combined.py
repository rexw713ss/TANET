"""Build licensed NewsQA combined CSV with CNN story_text under Python 3.

This is a narrow Python-3 port of Maluuba/newsqa's ``NewsQaDataset`` story
loading logic.  It preserves the project's newline and encoding correction
lists so BIPIA's answer offsets remain reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

import pandas as pd
from tqdm import tqdm


def read_id_set(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def story_map(stories_path: Path, story_ids: set[str], tools_dir: Path) -> dict[str, str]:
    extra_one = read_id_set(tools_dir / "stories_requiring_extra_newline.csv")
    extra_two = read_id_set(tools_dir / "stories_requiring_two_extra_newlines.csv")
    special = read_id_set(tools_dir / "stories_to_decode_specially.csv")
    remaining = set(story_ids)
    result: dict[str, str] = {}
    copyright_pattern = re.compile(r"^(Copyright|Entire contents of this article copyright, )")
    with tarfile.open(stories_path, mode="r:gz") as archive, tqdm(
        total=len(remaining), desc="Reading CNN stories", unit="stories"
    ) as progress:
        for member in archive:
            if member.name not in remaining or not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            raw_lines = extracted.readlines()
            if member.name in special:
                lines = ["".join(chr(byte) for byte in line.strip()) for line in raw_lines]
            else:
                lines = [line.strip().decode("utf-8") for line in raw_lines]
            try:
                highlights_start = lines.index("@highlight")
            except ValueError as exc:
                raise RuntimeError(f"Story has no @highlight marker: {member.name}") from exc
            story_lines = lines[:highlights_start]
            while story_lines and story_lines[-1] == "":
                story_lines.pop()
            while len(story_lines) > 1 and copyright_pattern.search(story_lines[-1]):
                story_lines = story_lines[:-2]
                while story_lines and story_lines[-1] == "":
                    story_lines.pop()
            separator = "\n\n\n" if member.name in extra_two else "\n\n" if member.name in extra_one else "\n"
            text = separator.join(story_lines)
            text = text.replace("\xe2\x80\xa2", "\xe2\u20ac\xa2")
            text = text.replace("\xe2\x82\xac", "\xe2\u201a\xac")
            text = text.replace("\r", "\n")
            if member.name in special:
                text = text.replace("\xe9", "\xc3\xa9")
            result[member.name] = text
            remaining.remove(member.name)
            progress.update(1)
            if not remaining:
                break
    if remaining:
        example = sorted(remaining)[:5]
        raise RuntimeError(f"Missing {len(remaining)} required stories; examples: {example}")
    return result


def repair_ranges(frame: pd.DataFrame) -> None:
    for row in tqdm(frame.itertuples(), total=len(frame), desc="Repairing answer ranges", unit="questions"):
        story_text = row.story_text
        ranges_updated = False
        updated_users = []
        for user_ranges in str(row.answer_char_ranges).split("|"):
            updated = []
            for char_range in user_ranges.split(","):
                if char_range == "None":
                    updated.append(char_range)
                    continue
                start, end = map(int, char_range.split(":"))
                if end > len(story_text):
                    end = len(story_text)
                    ranges_updated = True
                if start < end:
                    updated.append(f"{start}:{end}")
                else:
                    ranges_updated = True
            if updated:
                updated_users.append(",".join(updated))
        if ranges_updated:
            frame.at[row.Index, "answer_char_ranges"] = "|".join(updated_users)

        if row.validated_answers and not pd.isna(row.validated_answers):
            validated = json.loads(row.validated_answers)
            corrected = {}
            validated_updated = False
            for char_range, count in validated.items():
                if ":" not in char_range:
                    corrected[char_range] = count
                    continue
                start, end = map(int, char_range.split(":"))
                if end > len(story_text):
                    end = len(story_text)
                    validated_updated = True
                if start < end:
                    corrected[f"{start}:{end}"] = count
                else:
                    validated_updated = True
            if validated_updated:
                frame.at[row.Index, "validated_answers"] = json.dumps(
                    corrected, ensure_ascii=False, separators=(",", ":")
                )


def parse_args() -> argparse.Namespace:
    project = Path(__file__).resolve().parents[1]
    workspace = project.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--questions", type=Path, default=workspace / "datasets" / "newsqa" / "newsqa-data-v1.csv")
    parser.add_argument("--stories", type=Path, default=workspace / "datasets" / "newsqa" / "cnn_stories.tgz")
    parser.add_argument("--tools-dir", type=Path, default=workspace / "datasets" / "newsqa-tools" / "maluuba" / "newsqa")
    parser.add_argument(
        "--output", type=Path, default=workspace / "datasets" / "newsqa" / "combined-newsqa-data-v1.csv"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(
        args.questions,
        encoding="utf-8",
        dtype={"is_answer_absent": float},
        na_values={"question": [], "validated_answers": []},
        keep_default_na=False,
    )
    if "story_text" in frame.columns:
        raise ValueError("Questions input already contains story_text; refusing accidental overwrite")
    stories = story_map(args.stories, set(frame["story_id"]), args.tools_dir)
    frame["story_text"] = frame["story_id"].map(stories)
    repair_ranges(frame)
    columns = list(frame.columns)
    columns.insert(1, columns.pop(columns.index("story_text")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, columns=columns, index=False, encoding="utf-8")
    manifest = {
        "questions": str(args.questions.resolve()),
        "questions_sha256": sha256(args.questions),
        "stories": str(args.stories.resolve()),
        "stories_sha256": sha256(args.stories),
        "tools_dir": str(args.tools_dir.resolve()),
        "rows": len(frame),
        "unique_stories": len(stories),
        "output": str(args.output.resolve()),
        "output_bytes": args.output.stat().st_size,
        "output_sha256": sha256(args.output),
        "has_story_text": "story_text" in frame.columns and bool(frame["story_text"].str.len().min()),
    }
    manifest_path = args.output.with_name("combined-manifest.json")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
