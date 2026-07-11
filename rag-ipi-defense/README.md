# RAG 間接提示注入雙層防禦實驗

本專案已完成五任務 BIPIA 預註冊主實驗（含 WebQA）、Wilson／配對不確定性估計、family evaluator 獨立 audit、validation-only Gate 安全—成本曲線，以及 SRS 消融與任務／位置異質性分析。最新論文型總覽見工作區根目錄 [README](../README.md)，原始主實驗紀錄見 [2026-07-04 實驗狀態](docs/experiment-status-2026-07-04.md)。

兩個 context-disjoint sealed replications 的 pooled 核心結果：no-defense ASR 23.0% [15.84%, 32.15%]，two-stage ASR 1.0% [0.18%, 5.45%]；配對差 −22 percentage points [−29, −15]，exact McNemar `p=4.77e-7`。Pooled utility preservation 為 98.33%，benign block 3%，Tier-2 trigger 25%。v4 與 v5 各自的 ASR 差均為 −22 points。

Full Tier-2 Judge baseline 已在相同 100 IDs 完成：ASR 0% [0%, 7.13%]、utility preservation 94.68%、benign block 6%、Tier-2 trigger 100%。候選路由相較 always-on baseline 減少 74% Tier-2 calls，mean detector latency 約低 3.85 倍，並將 benign block 由 6% 降至 4%。

新增 external stability（固定既有 BIPIA Gate、不重新調參）：InjecAgent base PASS 98.39%、enhanced BLOCK 100%；HouYi offline seed PASS 67.22% [64.59%, 69.74%]，且 85 個情境群組中沒有任何一組能攔下全部 15 種變體。這些是 Tier-1 escape proxy，顯示現行方法對明顯 override wrapper 敏感，但對無 `ignore previous` 的 tool-action instructions 泛化不足。完整設計、MD5 相容模式與重現命令見工作區根目錄 [README](../README.md)。

## 論文正式方法設定

- 正式 `Dintent` 使用固定 revision 的 `intfloat/multilingual-e5-small`，不是字面關鍵字距離。
- Validation 選得 SRS 權重為 `alpha=0.6`、`beta=0.4`、`gamma=0.0`；pressure feature 保留於設計與消融，但正式權重為 0。
- Candidate-routed Gate 使用 `tau_low=tau_high=0.185`。數值 gray interval 已收斂，Tier-2 主要由 `directive_candidate` routing 觸發。
- External PASS rate 是 detector escape proxy，不是 downstream agent ASR。
- 正式名稱應使用「候選指令路由的雙層語意風險防禦」，不可描述成仍具有寬廣雙門檻灰區。

人工雙標目前由 Annotator A 完成 126 筆；第二位標註者應填 `results/family-evaluator-human/annotator_b_to_label.csv`，並遵守同目錄 `ANNOTATION_PROTOCOL.md`。

## 最新實驗輸出

- `results/main-holdout-v4/`：100 筆五任務主實驗與配對分析。
- `results/main-holdout-v5/`：100 筆 context-disjoint sealed replication。
- `results/sealed-replications-v4-v5/`：兩輪 pooled replication×task 統計。
- `results/family-evaluator-audit/`：31B 獨立複核與人工標註表。
- `results/gate-safety-cost/`：Gate Pareto curve。
- `results/tier2-validation-v3/`：30 筆 Tier-2 validation hard cases。
- `results/calibration/`、`results/gate-calibration-v2/`：只使用 validation 的門檻與權重。
- `results/external-stability/`：InjecAgent/HouYi 固定 Gate 穩定性結果。
- `results/research-synthesis/`：論文用消融、subgroup、latency 與 external class 分析。
- `results/family-evaluator-human/`：盲化雙人標註封包、agreement 與 adjudication 工具輸出。
- `results/full-tier2-baseline/`：相同 100 IDs 的 always-on structured Judge baseline。
- `results/external-two-stage-sample/`：預註冊 110 筆 external 完整 Gate 抽樣。

上述 main holdout、evaluator audit、Gate curve、calibration、external stability 與 research synthesis 結果均已作為 repository 研究產物保留；只有大型原始資料、模型 cache 與第三方 clone 由 `.gitignore` 排除。

## 執行測試

執行測試：

```powershell
.\env\Scripts\python.exe -m unittest discover -s .\rag-ipi-defense\tests -v
```

## 重建最新 validation 與主實驗

建立不讓 context 或 attack variant 跨越 fit/validation 的資料，並另外建立 official-test sample：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\scripts\prepare_experiment_splits.py `
  --test-contexts-per-task 100 --test-malicious-per-context 15
```

安裝本機 multilingual-E5 ONNX runtime，僅在 validation 選擇權重與門檻：

```powershell
.\env\Scripts\python.exe -m pip install -r .\rag-ipi-defense\requirements-embedding.txt
.\env\Scripts\python.exe .\rag-ipi-defense\src\calibrate_srs.py
```

主實驗資料已由 `main_holdout_v4_manifest.json` 鎖定。以下指令只供重現，不可再依 test 結果改 Gate：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\src\downstream_rag.py `
  --data .\rag-ipi-defense\data\splits\main_holdout_v4.jsonl `
  --methods no_defense,boundary_reminder,srs_only,two_stage `
  --tasks email,table,code,qa,abstract --limit-per-label-task 0 `
  --output-dir .\rag-ipi-defense\results\main-holdout-v4
```

Tier-2、Gate curve 與 family audit：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\src\evaluate_tier2_validation.py `
  --prompts v3 --per-label-task 3 --output-dir .\rag-ipi-defense\results\tier2-validation-v3
.\env\Scripts\python.exe .\rag-ipi-defense\src\gate_safety_cost_curve.py
.\env\Scripts\python.exe .\rag-ipi-defense\src\audit_family_evaluator.py `
  --predictions .\rag-ipi-defense\results\main-holdout-v4\predictions.jsonl `
  --independent-model gemma4:31b
```

## 匯入 BIPIA

WebQA 重建狀態記錄於 `data/bipia/webqa_reproduction.json`；目前公開官方輸入可完成內容重現，但無法重現 BIPIA repo 內建 exact MD5。

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\scripts\prepare_bipia_newsqa.py
```
