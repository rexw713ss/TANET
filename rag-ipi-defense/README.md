# RAG 間接提示注入雙層防禦實驗

本專案是研究計畫的實驗骨架。現有 `data/*.jsonl` 僅有 40 筆自建 smoke-test 樣本，用來確認程式與指標是否正常，**不是 BIPIA 主實驗結果**。

## 執行

離線執行不需本地模型的基準與消融：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\src\main_pipeline.py `
  --methods no_defense,keyword,srs_only,ablation_intent,ablation_instruction,ablation_pressure,ablation_all `
  --output-dir .\rag-ipi-defense\results\offline-smoke
```

執行完整雙層方法（需要 Ollama 與本地模型）：

```powershell
$env:OLLAMA_MODEL = "gemma4:latest"
.\env\Scripts\python.exe .\rag-ipi-defense\src\main_pipeline.py `
  --methods two_stage `
  --output-dir .\rag-ipi-defense\results\two-stage-smoke
```

執行測試：

```powershell
.\env\Scripts\python.exe -m unittest discover -s .\rag-ipi-defense\tests -v
```

每次實驗會輸出 `manifest.json`、`predictions.jsonl`、`metrics.json` 與 `metrics.csv`。`manifest.json` 記錄資料、模型、門檻、權重與已知限制。

## 指標解讀

- `detection_escape_rate_proxy` 是惡意樣本的分類假陰性率，不能直接稱為 ASR。
- 真正的 `attack_success_rate` 必須接上目標 RAG 模型，並判斷攻擊是否實際改變下游輸出。
- `utility_preservation` 必須有原任務參考答案或任務品質評估器，目前保持為 `null`。
- `auprc_average_precision` 使用 ranking-based Average Precision 計算。

完整落差與下一步見 [docs/research-alignment.md](docs/research-alignment.md)。

## 匯入 BIPIA

repo 內直接提供的 EmailQA、TableQA、CodeQA test split 可轉成目前 detector schema：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\scripts\import_bipia.py
```

輸出位於 `data/bipia/test_malicious.jsonl`、`test_benign.jsonl` 與 `manifest.json`。WebQA（NewsQA）與 Summarization（XSum）必須先依 BIPIA `benchmark/README.md` 閱讀來源條款並產生原始 context files；匯入器不會代替使用者接受條款。
