"""Download the official JBB-Behaviors harmful and benign splits."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


DATASET = "JailbreakBench/JBB-Behaviors"
CONFIG = "behaviors"
API = "https://datasets-server.huggingface.co/rows"


def fetch_split(split: str) -> list[dict]:
    query = urllib.parse.urlencode(
        {"dataset": DATASET, "config": CONFIG, "split": split, "offset": 0, "length": 100}
    )
    with urllib.request.urlopen(f"{API}?{query}", timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload["partial"] or len(payload["rows"]) != payload["num_rows_total"]:
        raise RuntimeError(f"Incomplete {split} split")
    return [{"split": split, **entry["row"]} for entry in payload["rows"]]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    output_dir = Path(__file__).resolve().parents[1] / "data" / "jailbreakbench"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "behaviors.jsonl"
    rows = fetch_split("harmful") + fetch_split("benign")
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest = {
        "dataset": DATASET,
        "config": CONFIG,
        "source": "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
        "doi": "10.57967/hf/2540",
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "counts": {"harmful": 100, "benign": 100},
        "file": {"name": output.name, "bytes": output.stat().st_size, "sha256": sha256(output)},
        "usage_note": "Auxiliary direct-jailbreak stress test only; do not merge into the BIPIA IPI headline result.",
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
