# Paper--experiment alignment audit (2026-07-19)

## Canonical result set used by the paper

The TANET paper uses the accepted 2026-07-18 shared-response paired rerun as its primary result set. The acceptance record is `results/rerun-2026-07-18/acceptance-report.json`.

- v4 predictions: `results/rerun-2026-07-18/v4-core-r2/predictions.jsonl`, SHA-256 `cfcb981333cbb774c42bc84c6b6c180359f125884a6dc279ed8d350a08f3b1c2`.
- v5 predictions: `results/rerun-2026-07-18/v5-core-r2/predictions.jsonl`, SHA-256 `10480d54830ffbefc752afdaa8accb71577fbed5aeedbf5dfe16f994b8423026`.
- Pooled analysis: `results/rerun-2026-07-18/pooled-r2/report.json`, SHA-256 `0683fbb676dedf8c0878baf674102d26d867b8fa7024be7d678543adced3df1a`.
- Automated acceptance status: accepted; zero generation errors, zero missing ASR labels, and verified byte-identical reuse for all eligible PASS pairs.

The paper does not use the older independently regenerated headline results in `results/main-holdout-v4`, `results/main-holdout-v5`, `results/sealed-replications-v4-v5`, or the headline/sealed portions of `results/research-synthesis/report.json`.

## Definition of v4 and v5

The names v4 and v5 are internal holdout identifiers, not BIPIA dataset release versions.

- **v4**: `data/splits/main_holdout_v4.jsonl`; first locked main holdout; selection seed 20260705; 10 previously unconsumed context groups in each of five tasks; one benign and one malicious row per context; 100 rows total; 24 nonzero BIPIA attack families. Source hash matches `data/splits/main_holdout_v4_manifest.json`.
- **v5**: `data/splits/next_holdout_v5.jsonl`; later locked replication; selection seed 20260712; excludes all v4 context groups; the same 10-contexts-per-task and paired-row design; 100 rows total; all 25 families, including Ransomware. Source hash matches `data/splits/next_holdout_v5_manifest.json`.
- Verified overlap: zero shared task/context groups and zero shared sample identifiers between v4 and v5.

## Primary numerical cross-check

| Paper quantity | v4 | v5 | Pooled | Canonical source |
|---|---:|---:|---:|---|
| No-screening ASR | 30% | 28% | 29% | corrected pooled report |
| Two-stage ASR | 2% | 0% | 1% | corrected pooled report |
| Paired ASR difference | -28 pp | -28 pp | -28 pp | corrected pooled report |
| Paired ASR 95% CI | [-40, -18] | [-40, -18] | [-36, -20] | corrected pooled report |
| No-screening benign utility | 0.628541 | 0.658733 | 0.643637 | corrected pooled report |
| Two-stage benign utility | 0.590247 | 0.620067 | 0.605157 | corrected pooled report |
| Paired utility difference | -0.03829 | -0.03867 | -0.03848 | corrected pooled report |
| Benign block rate | 6% | 4% | 5% | corrected pooled report |
| Malicious block rate | 92% | 88% | 90% | corrected pooled report |
| Tier-2 trigger rate | 26% | 24% | 25% | corrected pooled report |

The pooled exact McNemar result is `p=7.450580596923828e-09`, based on 28 baseline-only successes and zero method-only successes.

## Other paper result scopes

- **Always-On Tier-2**: the paper uses the corrected v4 rows in `v4-core-r2` and the accepted comparison embedded in `acceptance-report.json`: candidate/always-on ASR 2%/0%, benign block 6%/10%, utility 0.590247/0.576344, trigger 26%/100%, and mean detector latency 2.963/11.354 seconds. The older `results/full-tier2-baseline` headline comparison is not used for these paper values.
- **Human audit**: `results/family-evaluator-human/agreement_report.json` covers 126 legacy-v4 generated malicious outputs, not the corrected rerun. The paper reports the binary-resolved subset (`n=108`) and the adjudicated legacy-v4 sensitivity analysis only.
- **External sample**: `results/external-two-stage-sample/report.json` contains the pre-specified 110-row full-Gate sample. Its PASS rates are routing outcomes, not downstream agent ASR. The larger `results/external-stability/report.json` is a Tier-1 stability analysis and is not the paper's 110-row result.
- **Feature ablation**: the paper uses only the descriptive 380-row validation ablation in `results/research-synthesis/validation_ablation.csv`. It is not presented as independent test evidence.

## Interpretation boundaries now stated in the paper

- ASR is evaluator-labeled and depends on the local family-specific adapter; it is not treated as evaluator-free ground truth.
- Retrieved contexts are supplied directly; retriever recall is not measured.
- Task-level results are descriptive (`n=20` malicious and `n=20` benign per pooled task).
- The human audit covers legacy outputs only.
- External PASS is not downstream agent ASR.
- Latency is sequential and cache-sensitive.
- The primary generator, Tier-2 reviewer, and model-based evaluator share the Gemma 4 model family.

## Metadata clarification

The v4 corrected directory accumulated methods across resumed invocations. Its manifest now lists all accepted methods (`no_defense`, `srs_only`, `two_stage`, and `full_tier2`) and points readers to the acceptance report. For candidate routing, the operative thresholds are the `gate_policy` values `tau_low=tau_high=0.185`; the `srs_config` threshold fields are generic scorer defaults, and `srs_only_threshold=0.2` applies only to SRS Only.
