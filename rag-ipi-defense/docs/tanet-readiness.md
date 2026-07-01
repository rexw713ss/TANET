# TANET 投稿準備度與研究價值檢核

更新時間：2026-07-02

## 目前已完成

- 已接上 BIPIA 四個可用任務：EmailQA、TableQA、CodeQA、Summarization/XSum。
- 已 materialize detector 格式資料：
  - `data/bipia/test_malicious.jsonl`：63,750 筆 poisoned external contexts。
  - `data/bipia/test_benign.jsonl`：300 筆 clean contexts。
- 已取得 JailbreakBench JBB-Behaviors 200 筆作為 direct-jailbreak 輔助資料；不混入 BIPIA headline metrics。
- 已修正 Tier-1 `Rinstruction`，加入 BIPIA-style directive intrusion patterns，例如要求模型修改回答、插入廣告、改用編碼/語言、加入詐騙或錯誤資訊等。
- 已完成 unit tests：10 tests passed。
- 已完成 BIPIA offline full baseline v2。
- 已完成 BIPIA two-stage 小樣本 v4，並確認 Tier-2 是真實 Ollama/Gemma4 裁決，非 fail-closed error。

## NewsQA / WebQA 狀態

目前在 `D:\TANET` 找到的是：

- `D:\TANET\newsqa-data-v1.csv`

這個檔案只有 NewsQA 問題、答案區間與 `story_id`，沒有 CNN story 原文 `story_text`。BIPIA 的 WebQA 前處理需要 combined NewsQA context，或至少需要 CNN `.story` 原文，才能產出：

- `BIPIA/benchmark/qa/train.jsonl`
- `BIPIA/benchmark/qa/test.jsonl`

因此目前 WebQA 還不能完成。若之後補上 CNN stories 或官方 combined 檔，再執行 BIPIA `benchmark/qa/process.py` 並驗證 MD5。

## 最新實驗結果

### BIPIA offline full v2

資料：64,050 筆，含 63,750 malicious + 300 benign。

| method | recall | precision | F1 | FPR | escape proxy |
|---|---:|---:|---:|---:|---:|
| no_defense | 0.000 | n/a | n/a | 0.000 | 1.000 |
| keyword | 0.553 | 1.000 | 0.712 | 0.000 | 0.447 |
| srs_only | 0.553 | 1.000 | 0.712 | 0.000 | 0.447 |
| ablation_instruction | 0.553 | 1.000 | 0.712 | 0.000 | 0.447 |
| ablation_pressure | 0.041 | 0.995 | 0.079 | 0.040 | 0.959 |
| ablation_intent | 1.000 | 0.995 | 0.998 | 1.000 | 0.000 |

解讀：

- 目前有效訊號主要來自 `Rinstruction`。
- lexical Jaccard intent proxy 不可靠：單獨使用會全擋，FPR 100%。
- pressure signal 幫助很小。
- Tier-1 對 BIPIA 的明顯 output manipulation 類攻擊有用，但仍漏掉約 44.7%。

輸出位置：

- `results/bipia-offline-full-v2/metrics.csv`
- `results/bipia-offline-full-v2/metrics.json`
- `results/bipia-offline-full-v2/predictions.jsonl`

### BIPIA two-stage sample v4

抽樣設計：40 筆。

- 20 malicious：10 筆 Tier-1 REVIEW + 10 筆 Tier-1 PASS。
- 20 benign。

| method | recall | precision | F1 | FPR | Tier-2 trigger rate |
|---|---:|---:|---:|---:|---:|
| srs_only | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| two_stage | 0.500 | 1.000 | 0.667 | 0.000 | 0.250 |

Tier-2 裁決檢查：

- 10/10 triggered malicious 被 Gemma4 判為 `malicious / output_manipulation`。
- error count = 0。
- Tier-2 median latency when triggered：約 12.39 秒。
- Tier-2 p95 latency when triggered：約 34.73 秒，含模型載入/冷啟動影響。

解讀：

- Tier-2 能正確處理送進 REVIEW 的 BIPIA output manipulation。
- 但 two-stage 無法補救 Tier-1 已 PASS 的樣本；若 Tier-1 gate 太保守，整體 recall 仍受限。
- 因此下一步重點不是再堆 LLM，而是改善 Tier-1 gate：真 embedding intent score、better directive detection、或降低 `tau_low` 並讓 Tier-2 接更多灰區樣本。

輸出位置：

- `results/bipia-two-stage-sample-v4/metrics.csv`
- `results/bipia-two-stage-sample-v4/metrics.json`
- `results/bipia-two-stage-sample-v4/predictions.jsonl`

## TANET 創新性評估

我認為這個題目有 TANET 投稿價值，但要把「創新」講準，不要說成發明全新的 prompt-injection detector。

較有力的創新點：

1. **RAG 場景的雙層防禦架構**
   - 第一層用低成本 SRS 做快速 gate。
   - 第二層只對灰區使用 structured local adjudicator。
   - 價值在於兼顧成本、延遲、可解釋性與本地部署。

2. **把間接提示注入拆成可量測語意風險**
   - `Dintent`、`Rinstruction`、`Ppressure` 對應不同風險來源。
   - 比單純 keyword blacklist 更容易做消融與錯誤分析。

3. **結構化裁決輸出**
   - JSON schema 固定輸出 `risk_label / risk_type / evidence_span / confidence / short_reason`。
   - 可支援 audit trail，也比較符合資安/治理場景。

4. **本地模型裁決**
   - 避免把檢索內容送到外部 API。
   - 對教育、政府、校園網路與組織內知識庫情境較有實務價值。

5. **誠實區分 detector escape 與 downstream ASR**
   - 現有結果只報 detector false-negative proxy。
   - 不把 detector FN 亂稱成 attack success rate，這點在論文可信度上加分。

## 目前主要風險

1. **Tier-1 還不夠語意化**
   - 目前 intent 仍是 lexical Jaccard proxy。
   - TANET 論文若主張「語意風險」，需要補真正 embedding-based intent score。

2. **BIPIA benign 太少**
   - full test 只有 300 clean，相對 63,750 poisoned。
   - FPR 0% 不能過度宣稱，需要補外部 benign context，尤其中文/臺灣場景。

3. **沒有 downstream RAG ASR / utility**
   - 目前還沒有目標 RAG 生成器與任務答案評分器。
   - 所以只能說 detector-level results，不能說完整防禦成功率。

4. **Tier-2 latency 偏高**
   - 本地 Gemma4 triggered p50 約 12 秒，不適合即時高吞吐。
   - TANET 可定位為 prototype / offline-sensitive RAG defense，或補小模型/量化比較。

5. **NewsQA/WebQA 尚未完成**
   - 目前缺 CNN story text，不能 claim 完整 BIPIA 五任務。

## 建議投稿定位

建議題目走：

「面向校園/組織知識庫 RAG 的間接提示注入雙層語意風險防禦原型」

主張重點：

- 不是說模型已經全面勝過所有方法。
- 而是提出一個低成本 gate + 本地結構化裁決的防禦設計，並用 BIPIA 顯示：
  - keyword/SRS 可快速抓到一批 output manipulation。
  - LLM adjudicator 可對灰區樣本提供 evidence-based 判斷。
  - 目前瓶頸清楚落在 Tier-1 gate 與 downstream ASR 評估。

這樣寫會比較穩，也比較像一篇可信的 TANET 系統/資安應用論文。

## 下一步優先順序

1. 補 embedding-based intent score，取代 lexical Jaccard proxy。
2. 建立 validation split，用 BIPIA train 或自建樣本調 `tau_low/tau_high/tau_judge`。
3. 補 200–500 筆臺灣中文 benign external context。
4. 補中文/中英混合 IPI attack templates。
5. 建 downstream RAG harness，才正式回報 ASR 與 utility preservation。
6. 若時間允許，再補 NewsQA/CNN story text 完成 BIPIA WebQA。
