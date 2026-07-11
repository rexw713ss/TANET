# RAG 間接提示注入雙層防禦實驗

本專案已完成五任務 BIPIA 預註冊主實驗（含 WebQA）、Wilson／配對不確定性估計、family evaluator 獨立 audit、validation-only Gate 安全—成本曲線，以及 SRS 消融與任務／位置異質性分析。最新論文型總覽見工作區根目錄 [README](../README.md)，原始主實驗紀錄見 [2026-07-04 實驗狀態](docs/experiment-status-2026-07-04.md)。

主實驗的核心結果：no-defense ASR 24.0% [14.30%, 37.41%]，two-stage ASR 2.0% [0.35%, 10.50%]；配對差 −22 percentage points [−34, −12]，exact McNemar `p=0.0009766`。two-stage benign utility preservation 為 96.84%，Tier-2 trigger rate 26%。

新增 external stability（固定既有 BIPIA Gate、不重新調參）：InjecAgent base PASS 98.39%、enhanced BLOCK 100%；HouYi offline seed PASS 67.22% [64.59%, 69.74%]，且 85 個情境群組中沒有任何一組能攔下全部 15 種變體。這些是 Tier-1 escape proxy，顯示現行方法對明顯 override wrapper 敏感，但對無 `ignore previous` 的 tool-action instructions 泛化不足。完整設計、MD5 相容模式與重現命令見工作區根目錄 [README](../README.md)。

## 最新實驗輸出

- `results/main-holdout-v4/`：100 筆五任務主實驗與配對分析。
- `results/family-evaluator-audit/`：31B 獨立複核與人工標註表。
- `results/gate-safety-cost/`：Gate Pareto curve。
- `results/tier2-validation-v3/`：30 筆 Tier-2 validation hard cases。
- `results/calibration/`、`results/gate-calibration-v2/`：只使用 validation 的門檻與權重。
- `results/external-stability/`：InjecAgent/HouYi 固定 Gate 穩定性結果。
- `results/research-synthesis/`：論文用消融、subgroup、latency 與 external class 分析。

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
