# 研究計畫—實驗對齊紀錄

更新日期：2026-07-01

| 計畫項目 | 目前狀態 | 可宣稱範圍／缺口 |
|---|---|---|
| 外掛式雙層防禦 | 已具備實驗管線 | 尚未接入真正 RAG retriever 與 generator |
| Context boundary | 部分完成 | prompt 明確區分 trusted user task 與 untrusted context；尚無下游 Context Isolator |
| `Dintent` embedding 距離 | 未完成 | 目前是 `lexical_jaccard_proxy`；本機 Ollama 模型不支援 `/api/embed` |
| `Rinstruction`、`Ppressure` | 已實作 | 規則法只適合低成本 baseline，需在 validation split 校準 |
| `tau_low`／`tau_high` 分流 | 已實作 | 已移除針對單一 m015 樣本調門檻的資料洩漏式設定 |
| 結構化本地審查 | 已實作 | 固定 JSON schema、逐字 evidence、短理由、信心值；不要求自由式 CoT |
| 可稽核輸出 | 已實作 | 每筆 prediction 保存 Tier-1 特徵、匹配規則、Tier-2 JSON 與延遲 |
| BIPIA 主測試集 | 部分完成 | EmailQA、TableQA、CodeQA、Summarization 已建立；WebQA 尚缺 NewsQA 人工授權來源 |
| benign external context | 雛形 | 僅 20 筆，尚未形成具來源、任務類型與難例分層的測試集 |
| JailbreakBench 壓力測試 | 未完成 | 不應在主 IPI 結論中取代 BIPIA |
| No Defense、Regex、SRS Only | 實驗骨架完成 | No Defense 在目前分類器層只能表示全放行，不等於實測下游 ASR |
| Boundary Reminder | 未完成 | 需要目標 RAG 模型與輸出成功準則 |
| Single-Agent Local Judge | 可執行 | 使用 `--methods single_agent`；成本較高，應固定模型版本與 seed |
| Llama Guard 3 8B | 未完成 | 本機未安裝，不能虛構比較結果 |
| Precision／Recall／F1／AUPRC | 已實作 | 正式論文另需信賴區間與多次重複實驗 |
| p50／p95 latency、Trigger Rate | 已實作 | 正式量測需 warm-up、固定硬體與分離冷啟動結果 |
| ASR | 未完成 | 已停止把 detector FN rate 誤標為 ASR；需下游生成與攻擊成功 evaluator |
| Utility Preservation | 未完成 | 需任務參考答案或 judge rubric |
| Ablation | 已實作骨架 | intent/instruction/pressure/all 可執行；只能在正式 test set 上報告 |

## 正式實驗順序

1. 建立 BIPIA 與 benign set 的 train/validation/test manifest，避免同模板跨 split。
2. 接入可固定版本的 multilingual embedding 模型，將 lexical proxy 替換為 cosine distance。
3. 僅在 validation split 搜尋 SRS 權重、兩個分流門檻與 `tau_judge`。
4. 接上目標 RAG generator，定義各任務的攻擊成功與 utility 評估規則。
5. 完成 Boundary Reminder、Single-Agent、Llama Guard 比較；固定硬體、模型 digest、seed 與 warm-up。
6. 在封存的 test split 執行主要結果、消融、p50/p95 latency，並以 bootstrap 回報 95% CI。

## 目前結果的論文措辭

現階段結果只能描述為「原型管線與評估程式的可行性驗證」。在 BIPIA、下游 RAG ASR 與 utility 實驗完成前，不宜寫成「已證明能降低攻擊成功率」或「優於既有 guard」。

## 2026-07-01 smoke validation

- 40 筆資料中，Tier 1 直接 PASS 20 筆、直接 BLOCK 10 筆、REVIEW 10 筆，Tier-2 trigger rate 為 25%。
- 完整雙層方法的 detector precision、recall、F1 與 Average Precision 均為 1.0；這僅表示程式能處理目前的簡單人工樣本。
- 10 筆 REVIEW 全是惡意樣本，沒有良性灰區難例，因此這輪無法驗證 Tier 2 對模糊良性引文的 FPR。
- Tier 2 單筆 p50 為 10,738.18 ms、p95 為 11,339.06 ms；全資料端到端 p95 為 10,926.50 ms。
- Keyword baseline 也得到 F1 1.0，直接證明目前資料對規則法過於容易，而非完整方法已具優越性。
- `intent` 單特徵消融的 FPR 為 1.0，顯示 lexical Jaccard proxy 不適合作為正式語意偏移特徵。
