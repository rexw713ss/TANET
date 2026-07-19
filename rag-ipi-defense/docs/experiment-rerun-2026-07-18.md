# 2026-07-18 Gemma 4 paired rerun

## Why this rerun was needed

The legacy v4 table reported SRS-only utility preservation as 100.14%. The underlying values were valid arithmetic—`0.62903166 / 0.62815564 = 1.00139459`—but the presentation was misleading because a relative utility ratio is not a bounded accuracy measure. More importantly, the legacy harness independently regenerated an answer for every method even when No Defense, SRS Only, and Two Stage passed the same sample to an identical Gemma 4 prompt. Despite temperature 0 and a fixed seed, the local runtime did not always return byte-identical text, so tiny utility differences mixed defense effects with repeated-generation noise.

## Corrected protocol

- Keep the preregistered v4 and v5 manifests, validation-selected SRS weights, Gate thresholds, tasks, sample IDs, model tags, seeds, prompts, utility functions, and ASR evaluators unchanged.
- Run into a new result directory; do not overwrite the original sealed artifacts.
- For the same sample and effective generator prompt, reuse one Gemma 4 answer across methods that PASS.
- Reuse the family-evaluator result when the sample and answer are identical.
- A method that BLOCKS retains `[BLOCKED]`, zero downstream utility, and attack failure.
- Use paired benign-utility difference with task-stratified bootstrap CI as the primary utility comparison.
- Retain the utility ratio only as `relative benign utility`; do not describe it as a bounded percentage.

This is a measurement-protocol correction, not test-set recalibration: no SRS weight, threshold, routing rule, prompt, or evaluator decision rule is fit to the rerun outcomes.

## Gemma 4 configuration

| Role | Local model | Size / quantization | Seed | Ollama manifest ID |
|---|---|---|---:|---|
| Generation, Tier-2, primary model-evaluated family labels | `gemma4:latest` | 8.0B / Q4_K_M | 42 | `c6eb396dbd59` |
| Independent evaluator audit | `gemma4:31b` | 31.3B / Q4_K_M | 1729 | `6316f0629137` |

Both use temperature 0 in the experiment requests. Runtime and full model-blob SHA-256 provenance are stored in `results/model-provenance-2026-07-18.json`.

## Commands

```powershell
.\env\Scripts\python.exe -B .\rag-ipi-defense\src\downstream_rag.py `
  --data .\rag-ipi-defense\data\splits\main_holdout_v4.jsonl `
  --methods no_defense,srs_only,two_stage --limit-per-label-task 0 `
  --output-dir .\rag-ipi-defense\results\rerun-2026-07-18\v4-core-r2 --resume

.\env\Scripts\python.exe -B .\rag-ipi-defense\src\downstream_rag.py `
  --data .\rag-ipi-defense\data\splits\next_holdout_v5.jsonl `
  --methods no_defense,two_stage --limit-per-label-task 0 `
  --output-dir .\rag-ipi-defense\results\rerun-2026-07-18\v5-core-r2 --resume

.\env\Scripts\python.exe -B .\rag-ipi-defense\src\analyze_sealed_replications.py `
  --v4 .\rag-ipi-defense\results\rerun-2026-07-18\v4-core-r2\predictions.jsonl `
  --v5 .\rag-ipi-defense\results\rerun-2026-07-18\v5-core-r2\predictions.jsonl `
  --output-dir .\rag-ipi-defense\results\rerun-2026-07-18\pooled-r2
```

## Corrected core results

| Result | v4 | v5 | Pooled |
|---|---:|---:|---:|
| No-defense ASR | 30% [19.10, 43.75] | 28% [17.47, 41.67] | 29% [21.01, 38.54] |
| Two-stage ASR | 2% [0.35, 10.50] | 0% [0, 7.13] | 1% [0.18, 5.45] |
| Paired ASR difference | −28 points [−40, −18] | −28 points [−40, −18] | −28 points [−36, −20] |
| Exact McNemar p | 0.0001221 | 0.0001221 | 7.45×10⁻⁹ |
| No-defense benign utility | 0.628541 | 0.658733 | 0.643637 |
| Two-stage benign utility | 0.590247 | 0.620067 | 0.605157 |
| Paired utility difference | −0.03829 [−0.09236, 0] | −0.03867 [−0.09646, 0] | −0.03848 [−0.07526, −0.00957] |
| Benign block rate | 6% | 4% | 5% |
| Malicious block rate | 92% | 88% | 90% |
| Tier-2 trigger rate | 26% | 24% | 25% |

The effect direction is identical in both context-disjoint replications. The pooled utility CI no longer crosses zero, so the corrected experiment supports a measurable benign-utility cost; the paper must not retain the legacy statement that there was no clear utility decrease.

For the v4 SRS-only check, benign utility is exactly equal to No Defense (`0.6285406` for both), the paired difference and CI are `[0, 0]`, and relative benign utility is exactly 1.0. All 72 SRS-only PASS outputs and all 51 Two-stage PASS outputs were byte-identical to their paired No-defense Gemma 4 output and carried explicit reuse provenance. Both clean runs had zero generation errors and no missing ASR labels.

The first attempted output directory (`results/rerun-2026-07-18/v4`) is discarded: an interrupted Windows child process continued writing concurrently with a resumed process. It is excluded from every analysis. Only `v4-core-r2`, `v5-core-r2`, and `pooled-r2` are accepted.

The prior 126-row human adjudication remains valid for the legacy v4 generated answers, not these fresh outputs. It is retained as a separate evaluator-sensitivity analysis and is not represented as human validation of the corrected rerun.

## Corrected Full Tier-2 comparison (v4)

| Metric | Candidate-routed | Full Tier-2 |
|---|---:|---:|
| ASR | 2% | 0% |
| Benign block | 6% | 10% |
| Benign utility | 0.590247 | 0.576344 |
| Tier-2 trigger | 26% | 100% |
| Mean detector latency | 2,963.40 ms | 11,354.48 ms |

Candidate routing reduced Tier-2 calls by 74%; the observed Full/routed mean detector-latency ratio was 3.83. Full Tier-2 reduced ASR by a further 2 points but increased benign block by 4 points. Relative to No Defense, Full Tier-2's paired utility difference was −0.05220 [−0.10824, −0.00583]. Latency remains sequential and cache-sensitive.

Automated acceptance is stored in `results/rerun-2026-07-18/acceptance-report.json`. It verifies row counts, source hashes, zero generation errors, zero missing ASR labels, and byte-identical output/evaluator reuse for all eligible PASS pairs.
