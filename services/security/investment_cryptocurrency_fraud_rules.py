"""Scam/Fraud Type 13: detect investment and cryptocurrency fraud."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_INVESTMENT_RE = re.compile(
    r"\b(?:invest(?:ment|ing)?|portfolio|trading|trade|broker|adviser|advisor|fund|stock|shares?|"
    r"forex|foreign exchange|binary options?|copy trading|real estate investment|"
    r"cryptocurrency|crypto|bitcoin|ethereum|ether|usdt|tether|token|coin|defi|nft|"
    r"mining plan|staking|liquidity pool|crypto wallet|crypto exchange|trading platform)\b",
    re.I,
)
_SOLICITATION_RE = re.compile(
    r"\b(?:invest|deposit|send|transfer|wire|buy|purchase|convert|fund|top up|add funds?|"
    r"stake|subscribe|join|open)\b.{0,130}\b(?:money|funds?|cash|deposit|capital|investment|"
    r"account|wallet|bitcoin|ethereum|ether|usdt|tether|cryptocurrency|crypto|token|coin|"
    r"portfolio|trading plan|mining plan|staking plan|opportunity)\b"
    r"|\b(?:fund|top up|deposit into|send to|transfer to)\b.{0,100}\b(?:wallet|trading account|"
    r"investment account|broker account|platform)\b",
    re.I | re.S,
)
_IMPOSSIBLE_RETURN_RE = re.compile(
    r"\b(?:guaranteed|assured|fixed|risk[- ]free|zero risk|no risk|without risk|no losses?|"
    r"cannot lose|never lose|double|triple|10x|guaranteed income|guaranteed profit|"
    r"guaranteed returns?|guaranteed earnings?|\d{1,3}\s*%\s*(?:daily|weekly|per day|per week|"
    r"return|profit)|\d{2,4}\s*%\s*(?:return|profit)|98\s*%\s*win rate|100\s*%\s*win rate)\b",
    re.I,
)
_PRESSURE_RE = re.compile(
    r"\b(?:limited slots?|limited time|today only|act now|immediately|urgent|before (?:the )?price"
    r" (?:surges?|rises?)|presale ends?|private allocation|exclusive opportunity|secret tip|"
    r"insider tip|do not miss|last chance|whatsapp group|telegram group|private group)\b",
    re.I,
)
_WITHDRAWAL_LOCK_RE = re.compile(
    r"\b(?:withdrawal|profits?|returns?|investment balance|trading balance|crypto assets?)\b"
    r".{0,130}\b(?:locked|frozen|pending|held|restricted|cannot withdraw|can't withdraw|unlock|release)\b"
    r"|\b(?:pay|deposit|send|transfer)\b.{0,100}\b(?:tax|gas fee|unlock fee|release fee|"
    r"verification fee|upgrade fee|liquidity fee)\b.{0,100}\b(?:withdraw|withdrawal|release|unlock)\b",
    re.I | re.S,
)
_FAKE_ENDORSEMENT_RE = re.compile(
    r"\b(?:celebrity[- ]backed|celebrity endorsed|government backed|bank backed|secret algorithm|"
    r"ai trading bot|automatic trading bot|proven trading bot|guaranteed pump|pump group|"
    r"pre[- ]ipo allocation)\b",
    re.I,
)
_IRREVERSIBLE_RE = re.compile(
    r"\b(?:bitcoin|ethereum|ether|usdt|tether|cryptocurrency|crypto(?: wallet)?|personal wallet|"
    r"private wallet|personal broker account|over-the-counter wallet)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:investment scam|investment fraud|crypto(?:currency)? scam|crypto(?:currency)? fraud|"
    r"forex scam|binary options scam|pig[- ]butchering scam|fake trading platform|"
    r"fraudulent investment platform|token presale scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|past performance does not guarantee future results|"
    r"investments? can lose value|capital at risk|no guaranteed returns?|regulated prospectus|"
    r"licensed adviser|licensed advisor|official brokerage statement|transaction receipt|"
    r"market commentary only|educational webinar)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:investment fraud|crypto(?:currency)? fraud|forex scam|binary options fraud|"
    r"pig[- ]butchering|fake trading platform|token presale scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "investment_fraud_detected", "cryptocurrency_fraud_detected", "crypto_scam_detected",
        "fake_investment_platform_detected", "pig_butchering_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("investment_analysis", "cryptocurrency_analysis", "crypto_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner investment/cryptocurrency evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes investment or cryptocurrency fraud"
    investment = bool(_INVESTMENT_RE.search(text))
    solicitation = bool(_SOLICITATION_RE.search(text))
    impossible_return = bool(_IMPOSSIBLE_RETURN_RE.search(text))
    pressure = bool(_PRESSURE_RE.search(text))
    withdrawal_lock = bool(_WITHDRAWAL_LOCK_RE.search(text))
    fake_endorsement = bool(_FAKE_ENDORSEMENT_RE.search(text))
    irreversible = bool(_IRREVERSIBLE_RE.search(text))
    if investment and solicitation and impossible_return:
        return "investment solicitation promises impossible, guaranteed, or risk-free returns"
    if investment and solicitation and pressure and (fake_endorsement or irreversible):
        return "high-pressure investment solicitation requests funds through a risky crypto channel"
    if investment and withdrawal_lock and (solicitation or irreversible):
        return "supposed investment profits or withdrawals require another payment to be released"
    if investment and solicitation and fake_endorsement and (pressure or irreversible):
        return "investment pitch relies on fabricated endorsement or trading-system claims"
    return ""


def evaluate_investment_cryptocurrency_fraud_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type13-investment-cryptocurrency-fraud",
        points=100,
        reason=f"Investment or cryptocurrency fraud detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="investment-cryptocurrency-fraud",
    )]
