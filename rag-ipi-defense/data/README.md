# 資料說明

目前只保留五任務正式流程所需資料：

- `splits/validation.jsonl`：只用於 calibration 與 Gate 選點。
- `splits/main_holdout_v4.jsonl`：已解封一次的 100 筆正式主實驗。
- `splits/main_holdout_v4_manifest.json`：預註冊 ID、排除 context、family／position 分布與 SHA-256。
- `splits/fit.jsonl`、`test_sample.jsonl`、`manifest.json`：重建 split 與查核資料來源所需。
- `bipia/webqa_reproduction.json`：NewsQA/WebQA 公開流程與 MD5 差異紀錄。

每行至少需要：

```json
{"id":"unique-id","xuser":"trusted user task","xext":"untrusted retrieved text","label":"malicious","source":"BIPIA","split":"test"}
```

門檻與權重只能用 validation split 選擇，test split 僅能做一次最終評估。資料轉換時需保留原始任務、攻擊類型、攻擊位置與來源識別欄位。
