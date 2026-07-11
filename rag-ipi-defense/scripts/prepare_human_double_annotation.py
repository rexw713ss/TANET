"""Prepare two blinded evaluator-validation packets without overwriting annotations."""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "results" / "family-evaluator-audit" / "human_annotation_packet.csv"
PREDICTIONS = ROOT / "results" / "main-holdout-v4" / "predictions.jsonl"
OUTPUT = ROOT / "results" / "family-evaluator-human"
FIELDS = [
    "annotation_id",
    "task",
    "attack_family",
    "attack_name",
    "attack_instruction",
    "model_answer",
    "human_label",
    "human_notes",
]


def read_csv(path: Path) -> list[dict]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
        source_encoding = "utf-8-sig"
    except UnicodeDecodeError:
        text = raw.decode("cp950")
        source_encoding = "cp950"
    rows = list(csv.DictReader(text.splitlines()))
    for row in rows:
        row["_source_encoding"] = source_encoding
    return rows


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def main() -> None:
    existing = read_csv(SOURCE)
    invalid = [row for row in existing if row["human_label"].strip().upper() not in {"0", "1", "U"}]
    if invalid:
        raise ValueError("Annotator-A source must contain only 0, 1, or U labels")
    predictions = {
        (row["method"], row["id"]): row
        for row in read_jsonl(PREDICTIONS)
        if row["label"] == "malicious" and row.get("generated") and row.get("attack_success") is not None
    }
    prepared = []
    key_rows = []
    for row in existing:
        key = (row["method"], row["id"])
        prediction = predictions.get(key)
        if prediction is None:
            raise KeyError(f"Missing prediction for {key}")
        digest = hashlib.sha256(f"{row['method']}|{row['id']}".encode("utf-8")).hexdigest()[:12]
        annotation_id = f"H-{digest}"
        prepared.append({
            "annotation_id": annotation_id,
            "task": row["task"],
            "attack_family": row["attack_family"],
            "attack_name": row["attack_name"],
            "attack_instruction": prediction["attack_str"],
            "model_answer": row["answer"],
            "human_label": row["human_label"].strip().upper(),
            "human_notes": row["human_notes"],
        })
        key_rows.append({"annotation_id": annotation_id, "method": row["method"], "sample_id": row["id"]})
    if len({row["annotation_id"] for row in prepared}) != len(prepared):
        raise RuntimeError("Annotation ID collision")
    annotator_a = list(prepared)
    annotator_b = [{**row, "human_label": "", "human_notes": ""} for row in prepared]
    random.Random(20260711).shuffle(annotator_a)
    random.Random(20260712).shuffle(annotator_b)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_csv(OUTPUT / "annotator_a_completed.csv", FIELDS, annotator_a)
    write_csv(OUTPUT / "annotator_b_to_label.csv", FIELDS, annotator_b)
    write_csv(OUTPUT / "annotation_key.csv", ["annotation_id", "method", "sample_id"], key_rows)
    manifest = {
        "purpose": "Independent human validation of the BIPIA family-specific ASR evaluator.",
        "rows": len(prepared),
        "labels": {"0": "attack failed", "1": "attack succeeded", "U": "uncertain"},
        "annotator_a_source": "results/family-evaluator-audit/human_annotation_packet.csv",
        "annotator_a_source_encoding": existing[0]["_source_encoding"],
        "annotator_a_counts": dict(sorted(Counter(row["human_label"] for row in prepared).items())),
        "annotator_b_status": "blank; must be completed independently without opening annotation_key.csv or annotator_a_completed.csv",
        "blinding": "Packets omit method and all automated evaluator labels; row order differs by annotator.",
        "seeds": {"annotator_a_order": 20260711, "annotator_b_order": 20260712},
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
