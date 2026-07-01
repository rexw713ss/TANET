# 研究資料盤點

更新日期：2026-07-01

## 已取得

- BIPIA EmailQA、TableQA、CodeQA、Summarization/XSum 的官方 train/test contexts 與 attack templates。
- Detector test materialization：63,750 筆 poisoned contexts、300 筆 clean contexts，含 start/middle/end 位置。
- XSum 原始 Parquet；BIPIA context train 900/test 100 均通過官方 MD5。
- JailbreakBench JBB-Behaviors：100 harmful、100 benign，僅作 direct-jailbreak 輔助壓力測試。
- JailbreakBench 官方 artifacts repo：PAIR、GCG、JBC、DSN 與 random-search prompts；commit `909e68c01d94222b8ad2e397a017e2e12e2adb73`，獨立存放於 `datasets/JailbreakBench-artifacts`。
- 原型 local smoke set：20 malicious、20 benign，只用於程式驗證。

## 仍需人工取得

### BIPIA WebQA / NewsQA

Microsoft NewsQA 官方頁面要求使用者按下 `Agree & Download` 取得 questions/answers；CNN stories 另由 DeepMind Q&A Dataset 提供，原文章權利仍屬 CNN。取得並依 Maluuba NewsQA 工具合併成下列檔案後，才能執行 BIPIA `benchmark/qa/process.py`：

- `combined-newsqa-data-v1.csv`
- `combined-newsqa-data-v1.json`

BIPIA 最終應驗證：

- `qa/train.jsonl` MD5：`dabee926a5479290a6bc8eab24a149fa`
- `qa/test.jsonl` MD5：`1e973cc21ef6f0284bf5e7b509a60a1b`

## 正式論文仍需自建／標註

1. **臺灣中文 benign external context**：校務公告、資安通報、系統日誌、技術文件及中英混合文本；需保留來源、授權與任務類型。
2. **中文與中英混合 IPI**：至少涵蓋 instruction override、role escalation、task hijacking、output manipulation、data exfiltration，並包含正常引文與資安教學難例。
3. **Validation split**：只能用來選 SRS 權重、`tau_low`、`tau_high`、`tau_judge`；正式 test 不可參與調參。可從 BIPIA train templates 建立，但要依 context/template 分組避免洩漏。
4. **下游 RAG 評估資料**：每筆需有正常任務參考答案、攻擊成功判準與 utility 分數，才能計算真正 ASR 與 Utility Preservation。
5. **自適應攻擊集**：同義改寫、錯字、編碼、間接敘事及避免明顯命令詞的攻擊，用於測試規則與 SRS 的繞過風險。

JailbreakBench 不可取代 BIPIA 主結果；direct jailbreak 與 indirect prompt injection 必須分表呈現。
