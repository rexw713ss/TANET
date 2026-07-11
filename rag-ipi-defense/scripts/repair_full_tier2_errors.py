"""Prepare/finalize auditable retries for schema-truncated Full Tier-2 rows."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".repair.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    directory = root / "results" / "full-tier2-baseline"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "finalize"))
    parser.add_argument("--predictions", type=Path, default=directory / "predictions.jsonl")
    parser.add_argument("--manifest", type=Path, default=directory / "manifest.json")
    parser.add_argument("--provenance", type=Path, default=directory / "repair_provenance.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = read_jsonl(args.predictions)
    if args.action == "prepare":
        if args.provenance.exists():
            provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
            if provenance.get("status") == "pending":
                candidate_ids = {candidate["id"] for candidate in provenance["candidates"]}
                failures = [
                    row for row in rows
                    if row["id"] in candidate_ids and (row.get("tier2") or {}).get("error")
                ]
                if not failures:
                    raise RuntimeError("Pending provenance has no remaining failed rows")
                failed_ids = {row["id"] for row in failures}
                write_jsonl(args.predictions, [row for row in rows if row["id"] not in failed_ids])
                print(json.dumps({"status": "resumed", "remaining_ids": sorted(failed_ids)}, ensure_ascii=False, indent=2))
                return
        failures = [row for row in rows if (row.get("tier2") or {}).get("error")]
        if not failures:
            raise RuntimeError("No Tier-2 errors to repair")
        provenance = {
            "status": "pending",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "reason": "Retry only schema-truncated structured adjudicator JSON; no successful row is rerun.",
            "original_num_predict": 384,
            "retry_num_predict": 1024,
            "candidates": [
                {
                    "id": row["id"],
                    "label": row["label"],
                    "previous_decision": row["decision"],
                    "previous_error": row["tier2"]["error"],
                }
                for row in failures
            ],
        }
        args.provenance.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
        failed_ids = {row["id"] for row in failures}
        write_jsonl(args.predictions, [row for row in rows if row["id"] not in failed_ids])
        print(json.dumps(provenance, ensure_ascii=False, indent=2))
        return
    provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in rows}
    for candidate in provenance["candidates"]:
        repaired = by_id.get(candidate["id"])
        if repaired is None or (repaired.get("tier2") or {}).get("error"):
            raise RuntimeError(f"Repair incomplete for {candidate['id']}")
        candidate["repaired_decision"] = repaired["decision"]
        candidate["repaired_risk_label"] = repaired["tier2"]["risk_label"]
        candidate["repaired_confidence"] = repaired["tier2"]["confidence"]
    provenance["status"] = "complete"
    provenance["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    args.provenance.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    manifest["post_run_repairs"] = [
        {
            "provenance": "repair_provenance.json",
            "reason": provenance["reason"],
            "retry_num_predict": provenance["retry_num_predict"],
            "ids": [candidate["id"] for candidate in provenance["candidates"]],
        }
    ]
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
