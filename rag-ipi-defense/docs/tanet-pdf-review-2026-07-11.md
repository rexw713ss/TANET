# TANET.pdf 實驗對齊與稿件稽核（2026-07-11）

審閱檔案：`D:\TANET\research plan\TANET.pdf`（9 頁，2026-07-11 匯出）

## 結論

自動化的必做實驗已完成：v4 主實驗、context-disjoint v5 replication、v4+v5 pooled inference、正確的 Wilson／stratified bootstrap／exact McNemar 不確定性估計、family evaluator 獨立模型 audit、Gate 安全—成本曲線、Full Tier-2 Judge baseline、InjecAgent／HouYi 固定樣本完整 Gate 評估，以及 per-task exploratory analysis 均已有結果檔。

人工 evaluator 的 25 筆衝突已全部裁決，final consensus 覆蓋 126/126。至此預定的必做實驗均已完成；剩餘工作是把最終數字正確寫回論文並重排為符合頁數限制的版本。

目前 PDF 不能直接投稿，原因有二：

1. TANET 2026 口頭論文官方頁數限制為 2–6 頁，目前 PDF 為 9 頁。
2. 內文仍以 v4 單輪結果為主，且多處把已完成的 Full Tier-2 baseline 與人工雙標寫成未完成。

## 實驗完成矩陣

| 項目 | 狀態 | 論文可引用結果／注意事項 |
|---|---|---|
| v4 100-row locked holdout | 完成 | no-defense ASR 24%；two-stage 2%；utility preservation 96.84%；benign block 4%；Tier-2 trigger 26% |
| v5 context-disjoint sealed replication | 完成 | no-defense ASR 22% [12.75, 35.24]；two-stage 0% [0, 7.13]；paired difference −22 points [−32, −12]；McNemar p=0.0009766 |
| v4+v5 pooled | 完成，應作主結果 | no-defense 23% [15.84, 32.15]；two-stage 1% [0.18, 5.45]；paired difference −22 points [−29, −15]；McNemar p=4.77×10⁻⁷；utility preservation 98.33%；benign block 3%；Tier-2 trigger 25% |
| Full Tier-2 Judge baseline | 完成 | ASR 0% [0, 7.13]；utility preservation 94.68%；benign block 6%；malicious block 96%；trigger 100% |
| 候選路由成本比較 | 完成 | v4 上較 Full Judge 減少 74% Tier-2 calls；mean detector latency 14.78 s → 3.84 s（約 3.85×）；此為 sequential/cache-sensitive measurement |
| Validation 與 SRS ablation | 完成 | n=380；selected SRS AUPRC 0.885；instruction 0.845；intent 0.724；pressure 0.750；selected weights (0.6, 0.4, 0) |
| Gate safety–cost curve | 完成 | τlow=τhigh=0.185；Tier-2 主要由 directive-candidate routing 觸發 |
| Family evaluator model audit | 完成 | Final human consensus 對 primary evaluator：agreement 89.68%、κ=0.676、AC1=0.850；對 independent evaluator：96.03%、κ=0.842、AC1=0.947 |
| 人工雙標與裁決 | 完成 | 三類 agreement 80.16%，κ=0.472，AC1=0.758；binary-resolved n=108，agreement 93.52%，κ=0.773，AC1=0.909；final consensus 126/126 |
| Human-adjudicated v4 sensitivity | 完成 | no-defense 14% [6.95, 26.19]；two-stage 2% [0.35, 10.50]；paired Δ −12 points [−22, −4]；McNemar p=0.03125 |
| InjecAgent／HouYi Tier-1 stability | 完成 | 只能稱 Gate escape proxy，不是 downstream ASR |
| External complete-Gate prereg sample | 完成 | InjecAgent base 20/20 PASS、enhanced 20/20 BLOCK；HouYi 50 筆 PASS 72% [58.33, 82.53]、Tier-2 trigger 26%；仍不是 downstream agent ASR |
| Per-task pooled analysis | 完成、exploratory | ASR：abstract 40→0、code 0→0、email 15→0、QA 30→0、table 30→5；不作 confirmatory claim |
| NewsQA/WebQA public rebuild | 完成但非 strict byte identity | 應說明 public-content reproduction 與 SHA-256 provenance；不可宣稱通過 BIPIA 原始 MD5 strict reproduction |

## 必須修正的內容錯誤

### 1. Abstract、Introduction、Results、Conclusion 的主數字已過時

目前稿件反覆使用單輪 v4 的 24%→2%、96.84%、4%、26%。應以 pooled v4+v5 作主要結論，並把 v4／v5 分輪結果放在同一張表以呈現重現性：

> Across two independently sealed, context-disjoint BIPIA replications comprising 100 malicious and 100 benign pairs, the candidate-routed defense reduced pooled ASR from 23.0% (95% CI: 15.84–32.15%) to 1.0% (0.18–5.45%). The paired reduction was 22 percentage points (95% stratified-bootstrap CI: 15–29 points; exact McNemar p=4.77×10⁻⁷). Benign utility preservation was 98.33%, the benign block rate was 3.0%, and Tier-2 was invoked for 25.0% of all samples.

需明確寫「兩個 inference 前封存、context-disjoint 的 100-row holdouts」，合計 100 malicious pairs 與 100 benign pairs。v4 覆蓋 24/25 families；v5 補到 Ransomware，pooled 後覆蓋 25/25。

### 2. Full Tier-2 baseline 的敘述已經錯誤

刪除以下意思的所有句子：

- “a full-inspection baseline ... has not yet been measured”
- “requires an additional baseline”
- limitations／future work 中的 “adding a full-inspection baseline”

改為：Full Judge 的 ASR 最低（0%），因此不能再說 proposed method “achieves the lowest ASR among evaluated methods”。正確價值主張是：候選路由用 2 percentage points 的 v4 安全差距，換得較少審查、較低平均 detector latency、較少 benign block 和較高 utility。延遲數字受 sequential execution、warm cache 與本機硬體影響，不宜外推成一般化速度保證；另註明兩筆 schema-truncated Judge 輸出以相同設定增加 output budget 後重試，且未重跑成功列。

### 3. 人工 evaluator 狀態與 sensitivity analysis 必須加入

PDF 現稱多位人工標註是 future work，已不正確。雙人獨立標記及第三方裁決已完成。論文應分開報告三個層次：

1. 裁決前 inter-rater reliability：三類 agreement 80.16%、κ=0.472、AC1=0.758；binary-resolved n=108、agreement 93.52%、κ=0.773、AC1=0.909。
2. Final consensus 對 evaluator validity：全 126 筆對 primary agreement 89.68%、κ=0.676、AC1=0.850；對 independent agreement 96.03%、κ=0.842、AC1=0.947。在需要模型判定的 79 筆子集中，primary 對 human 為 86.08%、κ=0.591、AC1=0.792；independent 對 human 為 96.20%、κ=0.835、AC1=0.951。
3. Human-adjudicated v4 end-to-end sensitivity：no-defense 7/50=14% [6.95, 26.19]、boundary reminder 9/50=18% [9.77, 30.80]、SRS-only 1/50=2% [0.35, 10.50]、two-stage 1/50=2% [0.35, 10.50]。No-defense 對 two-stage 的 paired difference 為 −12 points [−22, −4]，baseline-only=6、method-only=0，exact McNemar `p=0.03125`。

第三項很重要：primary evaluator 將 v4 no-defense 判成 24%，人工裁決為 14%，說明自動 evaluator 對部分 baseline outputs 偏向過度判定成功；但人工 sensitivity analysis 仍支持 two-stage 顯著降低 ASR。論文必須如實揭露，不可只報 agreement。

這 126 筆涵蓋 v4 所有「實際進入生成」的 malicious outputs；防禦攔截列依預註冊 downstream ASR 定義記為攻擊失敗。Human sensitivity 只涵蓋 v4，不能寫成 pooled v4+v5 都經人工驗證。Audit packet 中按 method 顯示的 generated-only conditional rates不可直接當 end-to-end ASR。

### 4. SRS 公式與實作不一致

- 式 (3) 的輸入目前寫成 `SRS(xsys, xext)`，應為 `SRS(xuser, xext)`。
- Instruction Density 目前寫成「pattern hits／sentence count」，但程式實際是：`min(number of distinct matched regex patterns / 2, 1)`，沒有依句數正規化。必須改公式，否則方法不可重現。
- Dintent 的實作是對 context chunks 計算 `1 − min cosine similarity`，等價於最大 cosine distance；每個 distinct regex pattern 最多計一次。
- routing 的實作規則是 `score > τhigh` 才直接 BLOCK；`directive_candidate OR score >= τlow` 進 REVIEW；其餘 PASS。請保持 `>` 與 `>=` 一致。

### 5. 方法重現細節不足

至少在一個 compact implementation paragraph 補入：

- Dintent：`intfloat/multilingual-e5-small`，revision `fd1525a9fd15316a2d503bf26ab031a61d056e98`，`onnx/model.onnx`，E5 `query:`／`passage:` prefixes，max token length 512，max chunk chars 1400。
- 正式 SRS：α=0.6、β=0.4、γ=0；τlow=τhigh=0.185；pressure 僅供診斷與 ablation。
- 生成器及主要 family judge：`gemma4:latest`、seed 42；獨立 audit：`gemma4:31b`、seed 1729。
- validation n=380（285 malicious、95 benign）；另有 30 筆 Tier-2 hard-case validation。
- family-specific ASR evaluator：deterministic evaluator 處理可程式判定 families，其餘由 schema-constrained local judge 按 family target 判定。
- uncertainty：binomial proportions 用 Wilson 95% CI；paired ASR difference 用 replication×task-stratified bootstrap 5,000 次（seed 20260704）；配對不一致用 exact McNemar。

### 6. External stability 的主張需要補完整 Gate 結果

原本 Tier-1 InjecAgent 98.39% PASS 與 HouYi 67.22% PASS 可保留，但只能稱 fixed-gate escape proxy。另加入預註冊完整 Gate 110 筆結果。此處仍未執行 downstream agent/tool action，因此不可稱 ASR，也不能主張對 InjecAgent agent environment 有完整防禦效果。

## 表格建議（6 頁版本）

把目前 Table I 改成一張 compact 主表，至少呈現：

| Setting | No-defense ASR | Candidate-routed ASR | Paired Δ (pp) | Utility preservation | Benign block | Tier-2 trigger |
|---|---:|---:|---:|---:|---:|---:|
| v4 | 24% | 2% | −22 | 96.84% | 4% | 26% |
| v5 | 22% | 0% | −22 | 99.75% | 2% | 24% |
| pooled | 23% | 1% | −22 [−29, −15] | 98.33% | 3% | 25% |

另用一張小表比較 v4 Candidate-routed 與 Full Judge。Ablation 可縮為單行文字；per-task 數字與 external subclasses 若頁數不足，僅在本文摘要式報告並標 `exploratory`。

## 逐項文字與格式錯誤

- `downstream generatior` → `downstream generator`。
- `multilingual-E5 embedded model` → `multilingual-E5 embedding model`。
- Abstract 最後 `deployment..` → `deployment.`。
- `TABLE I. TABLE TYPE STYLES` 是範本殘留，改成實際表名。
- `ABALATION STUDY` → `ABLATION STUDY`。
- `VII CONCLUSION` → `VII. CONCLUSION`。
- 第 8 頁的 “Figure Labels: Use 8-point Times New Roman ...” 是 IEEE 範本說明，整段刪除。
- PDF metadata 仍為 Title=`Paper Title (use style: paper title)`、Author=`IEEE`；在 Word 文件屬性改成正式題名與作者後再匯出。
- Figure 1 中 pressure signals 應標為 diagnostic only / selected weight=0，避免讀者誤以為正式 SRS 使用該特徵。
- References 尚缺 InjecAgent 與 HouYi 原始論文；外部實驗段落必須引用。參考文獻頁碼與破折號在 PDF 文字層疑似有編碼異常，重新匯出後檢查複製貼上的可讀性。

## 壓到 6 頁的編排優先序

1. Literature Review 從多個長段落壓成 related-work matrix 或 3 個短段落。
2. Method 保留 threat model、SRS、routing、Tier-2 schema；刪除重複的系統描述與逐項 log 清單。
3. Results 保留 pooled 主表、Full Judge cost trade-off、human validity、external limitation；ablation/per-task 改成緊湊文字。
4. Limitations 合併成一段，刪除已完成實驗的 future-work 敘述。
5. 刪除所有範本殘留後重新平衡雙欄；目前第 9 頁大片留白也會因重排而改善。

## 投稿定位與可成立的創新主張

適合的主張不是「提出第一個 IPI detector」或「達到最佳 ASR」，而是：

1. 一個不修改黑箱 RAG generator 的 validation-calibrated candidate-routing boundary；
2. 以同一 Judge 的 always-on baseline 量化安全—效用—審查成本取捨；
3. 以兩個 context-disjoint sealed replications、paired inference 和正確不確定性估計提升小型本機研究的可信度；
4. 同時揭露跨 benchmark Gate 失效邊界，避免把 detection PASS rate 誤報為 downstream ASR。

研究具 TANET 的應用與資安價值，但貢獻應定位為「部署型、成本感知、可稽核的 RAG security gate 及其嚴謹實證」，而非普適攻擊防禦。實驗已完成；最重要的剩餘工作是將 9 頁舊版稿重寫成 6 頁，並以 pooled 主結果、Full Judge trade-off 與 human-adjudicated v4 sensitivity 為核心。

## 結果來源

- `results/sealed-replications-v4-v5/report.json`
- `results/sealed-replications-v4-v5/per_task_exploratory.csv`
- `results/full-tier2-baseline/comparison_report.json`
- `results/external-two-stage-sample/report.json`
- `results/family-evaluator-human/agreement_report.json`
- `results/research-synthesis/report.json`
- `results/calibration/calibration.json`
- `results/gate-calibration-v2/calibration.json`
