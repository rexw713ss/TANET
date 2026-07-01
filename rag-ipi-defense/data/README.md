# 資料說明

`malicious.jsonl` 與 `benign.jsonl` 各含 20 筆人工撰寫樣本，來源標記預設為 `local_smoke`。用途是驗證 I/O、規則、分流、結構化審查與評估程式，不應用來支持泛化能力或與既有方法的優劣結論。

正式實驗匯入 BIPIA 或其他資料時，每行至少需要：

```json
{"id":"unique-id","xuser":"trusted user task","xext":"untrusted retrieved text","label":"malicious","source":"BIPIA","split":"test"}
```

門檻與權重只能用 validation split 選擇，test split 僅能做一次最終評估。資料轉換時需保留原始任務、攻擊類型、攻擊位置與來源識別欄位。
