"""Build BIPIA abstract context files from public XSum Parquet files."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import jsonlines
import pyarrow as pa
import pyarrow.parquet as pq


def md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def selected_rows(path: Path, indexes: list[int]) -> list[dict]:
    """Read selected global row indexes without loading the whole Parquet file."""
    parquet = pq.ParquetFile(path)
    requests: dict[int, list[tuple[int, int]]] = defaultdict(list)
    offset = 0
    sorted_indexes = sorted(enumerate(indexes), key=lambda pair: pair[1])
    request_index = 0
    for row_group in range(parquet.num_row_groups):
        row_count = parquet.metadata.row_group(row_group).num_rows
        while request_index < len(sorted_indexes):
            output_position, global_index = sorted_indexes[request_index]
            if global_index >= offset + row_count:
                break
            if global_index < offset:
                raise IndexError(global_index)
            requests[row_group].append((output_position, global_index - offset))
            request_index += 1
        offset += row_count
    if request_index != len(sorted_indexes):
        raise IndexError(f"Parquet has {offset} rows; requested {sorted_indexes[request_index][1]}")

    output: list[dict | None] = [None] * len(indexes)
    for row_group, selections in requests.items():
        table = parquet.read_row_group(row_group, columns=["document", "summary"])
        local_indexes = pa.array([local_index for _, local_index in selections])
        rows = table.take(local_indexes).to_pylist()
        for (output_position, _), row in zip(selections, rows):
            output[output_position] = row
    return [row for row in output if row is not None]


def write_contexts(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        writer = jsonlines.Writer(handle)
        writer.write_all(
            {"ideal": row["summary"], "context": row["document"]} for row in rows
        )
        writer.close()


def expected_md5(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        value, filename = line.split("  ")
        result[filename] = value
    return result


def parse_args() -> argparse.Namespace:
    workspace = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xsum-dir", type=Path, default=workspace / "datasets" / "xsum")
    parser.add_argument("--bipia-root", type=Path, default=workspace / "BIPIA")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = args.bipia_root / "benchmark" / "abstract"
    indexes = json.loads((target / "index.json").read_text(encoding="utf-8"))
    expected = expected_md5(target / "md5.txt")
    outputs = {}
    for split in ("train", "test"):
        rows = selected_rows(args.xsum_dir / f"{split}.parquet", indexes[split])
        output = target / f"{split}.jsonl"
        write_contexts(output, rows)
        actual = md5(output)
        outputs[split] = {"rows": len(rows), "md5": actual, "expected_md5": expected[output.name]}
        if actual != expected[output.name]:
            raise RuntimeError(f"{output.name} MD5 mismatch: {actual} != {expected[output.name]}")
    source_manifest = {
        "dataset": "EdinburghNLP/xsum",
        "source": "https://huggingface.co/datasets/EdinburghNLP/xsum/tree/main/data",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "license_on_huggingface": "unknown",
        "usage_note": "Review the XSum source guidelines before redistribution or publication.",
        "files": {},
        "bipia_outputs": outputs,
    }
    for split in ("train", "test"):
        source = args.xsum_dir / f"{split}.parquet"
        source_manifest["files"][source.name] = {
            "bytes": source.stat().st_size,
            "sha256": sha256(source),
        }
    (args.xsum_dir / "manifest.json").write_text(
        json.dumps(source_manifest, indent=2), encoding="utf-8"
    )
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
