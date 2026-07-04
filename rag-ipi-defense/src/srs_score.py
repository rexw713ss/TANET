"""Tier-1 Semantic Risk Score (SRS) features.

The current intent feature is deliberately named ``lexical_jaccard_proxy``.
It keeps the smoke experiment dependency-free, but it is not a substitute for
the embedding distance specified by the research proposal.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Protocol


INSTRUCTION_PATTERNS = (
    r"ignore (?:all |any )?(?:previous|prior|earlier) instructions?",
    r"ignore the security policy",
    r"do not (?:answer|summari[sz]e|follow)",
    r"stop (?:following|the current task)",
    r"follow only this instruction",
    r"higher priority than (?:the )?(?:user|system)",
    r"system override",
    r"(?:reveal|print|output|disclose) (?:the )?(?:system prompt|developer message|hidden instructions?|confidential context)",
    r"(?:bypass|disable) (?:the )?(?:guardrail|safety|policy)",
    r"classify this incident as harmless",
    r"you are now|new role|new instructions?",
    # BIPIA-style indirect prompt injection often does not say "ignore
    # previous instructions"; it asks the model to alter the final answer,
    # reply format, or generated code from inside retrieved context.
    r"(?:add|append|include|integrate|insert|incorporate|embed|feature)\b.{0,120}\b(?:in|into|to|within)\b.{0,80}\b(?:your|the)\b.{0,40}\b(?:answer|response|reply|message|output|code|implementation|solution)",
    r"(?:modify|enhance|augment|rewrite|render|translate|encode|encrypt|reverse|substitute|replace)\b.{0,120}\b(?:your|the)\b.{0,40}\b(?:answer|response|reply|message|output)",
    r"(?:provide|write|show|suggest|recommend|determine|analy[sz]e|classify|summari[sz]e)\b.{0,120}\b(?:your|the)\b.{0,40}\b(?:answer|response|reply|message|output)",
    r"(?:use|reply using|provide your answer in|express your answer using)\b.{0,80}\b(?:base64|base32|base16|base58|caesar cipher|substitution cipher|emoji|emojis|reverse|spanish|french|german|italian|portuguese)",
    r"(?:click this link|visit www\.|subscribe to|share (?:their|your) bank details|claim your unexpected lottery winnings)",
    r"(?:fabricated statistic|false claim|baseless rumor|misleading statement|fake antivirus|too-good-to-be-true)",
    r"(?:add|append|include|integrate|insert|incorporate|embed|feature|merge|employ|utili[sz]e|leverage)\b.{0,120}\b(?:code snippet|code block|code excerpt|code section)",
    r"不要(?:遵守|理會|摘要)",
    r"(?:請)?忽略(?:所有|前面|之前|原本)?",
    r"停止(?:回答|目前任務|原本任務)",
    r"(?:改成|改為)(?:輸出|回答|要求)",
    r"原本的回答改成",
    r"只服從|覆寫(?:規則|指令)",
    r"你現在是|最高權限",
    r"(?:輸出|洩漏|揭露)(?:所有)?(?:系統提示|內部提示|隱藏規則|內部規則|機密)",
    r"系統已被成功控制",
)

PRESSURE_PATTERNS = (
    r"\bmust\b",
    r"\burgent\b",
    r"\bimmediately\b",
    r"do not refuse",
    r"必須|立即|不得拒絕|否則|強制",
)


@dataclass(frozen=True)
class SRSConfig:
    alpha: float = 0.15
    beta: float = 0.70
    gamma: float = 0.15
    tau_low: float = 0.30
    tau_high: float = 0.70
    instruction_saturation_hits: float = 2.0
    pressure_saturation_hits: float = 2.0
    intent_method: str = "lexical_jaccard_proxy"

    def validate(self) -> None:
        if min(self.alpha, self.beta, self.gamma) < 0:
            raise ValueError("SRS weights must be non-negative")
        if self.alpha + self.beta + self.gamma <= 0:
            raise ValueError("At least one SRS weight must be positive")
        if not 0 <= self.tau_low <= self.tau_high <= 1:
            raise ValueError("Thresholds must satisfy 0 <= tau_low <= tau_high <= 1")


def simple_tokens(text: str) -> set[str]:
    """Return dependency-free tokens for the lexical intent proxy."""
    text = text.casefold()
    english_words = re.findall(r"[a-z]+", text)
    chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
    return set(english_words + chinese_chars)


def intent_shift_score(xuser: str, xext: str) -> float:
    user_tokens = simple_tokens(xuser)
    ext_tokens = simple_tokens(xext)
    if not user_tokens or not ext_tokens:
        return 0.0
    return 1.0 - (len(user_tokens & ext_tokens) / len(user_tokens | ext_tokens))


class IntentScorer(Protocol):
    method: str

    def score(self, xuser: str, xext: str) -> float: ...


def pattern_density_score(
    text: str, patterns: Iterable[str], saturation_hits: float = 2.0
) -> tuple[float, list[str]]:
    matches = [pattern for pattern in patterns if re.search(pattern, text, re.IGNORECASE)]
    score = min(len(matches) / saturation_hits, 1.0)
    return score, matches


def compute_srs(
    xuser: str,
    xext: str,
    config: SRSConfig | None = None,
    enabled_features: tuple[str, ...] = ("intent", "instruction", "pressure"),
    intent_scorer: IntentScorer | None = None,
) -> dict:
    """Compute an SRS record, normalizing weights for feature ablations."""
    config = config or SRSConfig()
    config.validate()

    intent = (
        intent_scorer.score(xuser, xext)
        if intent_scorer is not None
        else intent_shift_score(xuser, xext)
    )
    instruction, instruction_matches = pattern_density_score(
        xext, INSTRUCTION_PATTERNS, config.instruction_saturation_hits
    )
    pressure, pressure_matches = pattern_density_score(
        xext, PRESSURE_PATTERNS, config.pressure_saturation_hits
    )

    values = {"intent": intent, "instruction": instruction, "pressure": pressure}
    weights = {
        "intent": config.alpha,
        "instruction": config.beta,
        "pressure": config.gamma,
    }
    unknown = set(enabled_features) - set(values)
    if unknown:
        raise ValueError(f"Unknown SRS features: {sorted(unknown)}")
    denominator = sum(weights[name] for name in enabled_features)
    if denominator <= 0:
        raise ValueError("Enabled SRS features have zero total weight")

    srs = sum(weights[name] * values[name] for name in enabled_features) / denominator
    if srs < config.tau_low:
        decision = "PASS"
    elif srs > config.tau_high:
        decision = "BLOCK"
    else:
        decision = "REVIEW"

    return {
        "intent_shift": round(intent, 6),
        "instruction_density": round(instruction, 6),
        "pressure_signal": round(pressure, 6),
        "srs": round(srs, 6),
        "tier1_decision": decision,
        "intent_method": intent_scorer.method if intent_scorer is not None else config.intent_method,
        "enabled_features": list(enabled_features),
        "instruction_matches": instruction_matches,
        "pressure_matches": pressure_matches,
    }


def evaluate_tier1(
    xuser: str, xext: str, tau_low: float = 0.30, tau_high: float = 0.70
) -> tuple[str, float]:
    """Compatibility wrapper for the original experiment scripts."""
    record = compute_srs(xuser, xext, SRSConfig(tau_low=tau_low, tau_high=tau_high))
    return record["tier1_decision"], record["srs"]


def load_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect Tier-1 SRS values")
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    base_dir = Path(__file__).resolve().parent.parent
    paths = args.paths or [base_dir / "data" / "splits" / "validation.jsonl"]
    config = SRSConfig()
    print(json.dumps({"config": asdict(config)}, ensure_ascii=False))
    for path in paths:
        for item in load_jsonl(path):
            print(json.dumps({**item, **compute_srs(item["xuser"], item["xext"], config)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
