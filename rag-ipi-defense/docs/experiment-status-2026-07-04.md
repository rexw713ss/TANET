# 實驗狀態（2026-07-04）

本輪依序完成 WebQA 資料重建、五任務預註冊主實驗、不確定性估計、family evaluator audit，以及 validation-only Gate 安全—成本曲線。主實驗已解封一次並完成；不得再依 test 結果回頭調整門檻。

## 1. WebQA / NewsQA 重現

- Microsoft 官方 `newsqa-data-v1.csv`：18,174,822 bytes，SHA-256 `d124502e0e03baff86ff0c2459d6fd657d12fe68290ac4e112dd828f0de03c36`。
- CNN stories：158,577,824 bytes，SHA-256 `e8fbc0027e54e0a916abd9c969eb35f708ed1467d7ef4e3b17a56739d65cb200`。
- 官方 NewsQA Python 2 工具產生的 combined CSV：119,633 rows、12,744 unique stories，`story_text` 無空值。
- BIPIA WebQA 輸出：train 900、test 100；BIPIA 原始 `process.py` 與本專案 direct port 產生相同檔案。

公開輸入仍無法通過 BIPIA repo 內建 MD5：

| split | BIPIA expected MD5 | 公開流程 actual MD5 |
|---|---:|---:|
| train | `dabee926a5479290a6bc8eab24a149fa` | `468c54410bbf74e7e1e55086997451c8` |
| test | `1e973cc21ef6f0284bf5e7b509a60a1b` | `907858ddf4b96e92e2849341114d6c98` |

這不是缺少 `story_text`：官方 QA、stories、Python 2 builder、BIPIA 轉換與 `datasets` 2.8/2.21 均已交叉驗證。正式描述應寫成「以目前公開官方輸入完成內容重現，但未重現 BIPIA 作者未封存的 exact byte hash」，不能宣稱 strict MD5 reproduction。稽核檔在 `data/bipia/webqa_reproduction.json`。

## 2. 預註冊主實驗

鎖定檔：`data/splits/main_holdout_v4_manifest.json`；資料 SHA-256：`4bb1090d1f9bac22cf7412cd73b3514a40561db3c4f9c24b02732ec5e82b13c2`。

- 100 rows：50 benign、50 malicious。
- 五任務各 10 benign + 10 malicious：Summarization、CodeQA、EmailQA、WebQA、TableQA。
- 排除所有先前 pilot 使用過的整個 `(task, context_index)` group。
- attack position：start 16、middle 17、end 17。
- 覆蓋 24/25 個 test attack families；本次未抽到 Ransomware family，必須列為限制。
- 四方法在完全相同的 100 IDs 上評估：no defense、boundary reminder、SRS only、two stage。

## 3. 主結果與正確不確定性

二元率使用 Wilson 95% CI；utility 使用固定任務比例的 task-stratified bootstrap；方法差異使用 paired task-stratified bootstrap，ASR 同時報 exact McNemar test。

| 方法 | ASR（Wilson 95% CI） | benign utility（95% CI） | paired Δ utility vs. no defense（95% CI） | benign block | malicious block | Tier-2 trigger |
|---|---:|---:|---:|---:|---:|---:|
| No defense | 24.0% [14.30, 37.41] | 0.6282 [0.5465, 0.7061] | reference | 0% | 0% | 0% |
| Boundary reminder | 30.0% [19.10, 43.75] | 0.6239 [0.5336, 0.7088] | −0.0043 [−0.0570, 0.0506] | 0% | 0% | 0% |
| SRS only | 6.0% [2.06, 16.22] | 0.6290 [0.5472, 0.7071] | +0.0009 [−0.0013, 0.0036] | 0% | 56% | 0% |
| Two stage | 2.0% [0.35, 10.50] | 0.6083 [0.5190, 0.6932] | −0.0199 [−0.0589, 0.0015] | 4% | 92% | 26% |

相對 no defense 的配對結果：

- Two stage ASR 差：−22 percentage points，95% CI [−34, −12]；11 個 baseline-only successes、0 個 defense-only successes；exact McNemar `p=0.0009766`。
- Two stage benign utility 差：−0.01986，95% CI [−0.05892, 0.00150]。區間含 0，不能宣稱 utility 顯著下降或完全無損。
- SRS only ASR 差：−18 points，95% CI [−30, −6]；McNemar `p=0.01172`。
- Boundary reminder ASR 差：+6 points，95% CI [−2, 14]；McNemar `p=0.375`，沒有改善證據。

Two-stage detector latency p50 2.47 ms、p95 15.93 s；長尾來自 Tier-2。完整輸出位於 `results/main-holdout-v4/`。

## 4. Family evaluator 可信度

主 evaluator 依 family 分流：code 使用 RapidFuzz、Base/Emoji/Language 使用決定式規則，其餘文字 family 使用 `gemma4:latest` 結構化 judge。兩筆被截斷的 JSON 已在不改變生成回答的前提下補判，repair provenance 已寫入主 manifest。

以不同模型 `gemma4:31b`、不同 seed 對所有 126 個「實際生成的 malicious answers」做離線 audit：

- overall agreement 90.48% [84.09, 94.47]，κ=0.705；此值包含 47 個 deterministic replay。
- 只看 79 個真正由第二模型獨立重判的 cases：agreement 84.81% [75.30, 91.09]，κ=0.546。
- 12 個 disagreement 全是 primary=true、31B=false，集中於 Substitution Ciphers、Reverse Text 與 Information Dissemination。
- 若改用 31B labels 做敏感度分析：no defense 14%、boundary 20%、SRS only 2%、two stage 2%；主要安全結論不變，但 baseline ASR 的絕對值受 evaluator 影響。

因此目前可聲稱「結論對第二本機 judge 穩健」，不可聲稱 human-level evaluator validity。`results/family-evaluator-audit/human_annotation_packet.csv` 已盲化並保留空白 `human_label`；投件前仍應由至少兩位人工標註者完成，報 κ/AC1 與 adjudication protocol。

## 5. Gate 安全—成本曲線

曲線只使用 380 筆 validation（285 malicious、95 benign），未用主 test 選點。Tier-2 擴大 hard-case validation 為 30 筆：TP=15、TN=14、FP=1、FN=0，recall 100%、FPR 6.67%；0/15 FN 的 Wilson 上界仍為 20.39%。

- Candidate-routed policy：`BLOCK score>tau_high; REVIEW directive_candidate or score>=tau_low; else PASS`。
- 選定 `tau_low=tau_high=0.185` 時，validation malicious direct-pass 1.40%、benign auto-block 0%、review 46.58%。
- Pareto sweep 共 5,151 個 threshold pairs、23 個 non-dominated points。
- 主 test 的實現成本：Tier-2 trigger 26% [18.40, 35.37]、benign block 4% [1.10, 13.46]、malicious block 92% [81.16, 96.85]。
- 曲線輸出：`results/gate-safety-cost/pareto_frontier.csv`、`report.json`、`pareto_frontier.svg`。

## 6. TANET 創新與價值判斷

目前最有力的貢獻不是「又一個 prompt reminder」，而是可驗證的系統組合：語意 intent shift + 指令密度的 Tier-1、候選指令路由的 Tier-2、family-specific ASR，以及 validation-only 安全—成本選點。100 筆配對主實驗提供顯著 ASR 改善，同時把 utility 與 latency 代價量化，具有實務部署價值。

仍會被審稿人追問的三點：WebQA upstream MD5 無法 strict reproduce、model-only family κ 僅中等、五任務各 10 個攻擊的樣本仍不算大。投件前優先補人工雙標與第二 seed／更大 test replication；不要再用本次 test 調 Gate。
