# BIPIA detector test data

由 `scripts/import_bipia.py` 從 `microsoft/BIPIA` commit `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` 建立，seed 為 2023。

- `test_malicious.jsonl`：63,750 筆 poisoned full contexts。
- `test_benign.jsonl`：300 筆原始 clean contexts。
- 任務：EmailQA、TableQA、CodeQA、Summarization/XSum。
- 攻擊位置：start、middle、end。
- `manifest.json`：來源 commit、參數、筆數、檔案大小與 SHA-256。

資料包含刻意植入的惡意提示，只能視為不可信測試輸入，不應直接送入具工具權限的代理系統。

執行不呼叫 Tier 2 的初步基準：

```powershell
.\env\Scripts\python.exe .\rag-ipi-defense\src\main_pipeline.py `
  --data .\rag-ipi-defense\data\bipia\test_malicious.jsonl .\rag-ipi-defense\data\bipia\test_benign.jsonl `
  --methods keyword,srs_only `
  --output-dir .\rag-ipi-defense\results\bipia-test-offline
```

請勿直接在完整資料上執行 `two_stage`：以目前每筆 Tier 2 約 11 秒估算，可能需要數十小時。應先決定抽樣或批次策略。
