"""Scam/Fraud Type 3: detect prize, lottery, sweepstakes, and inheritance scams."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_PRIZE_RE = re.compile(
    r"\b(?:prize|award|reward|jackpot|lottery|sweepstakes?|raffle|cash draw|winning ticket|"
    r"winner|winnings?|grand prize)\b",
    re.I,
)
_INHERITANCE_RE = re.compile(
    r"\b(?:inheritance|bequest|estate funds?|unclaimed estate|next of kin|beneficiary|"
    r"deceased client|late client|family fortune|inheritance fund)\b",
    re.I,
)
_WIN_CLAIM_RE = re.compile(
    r"\b(?:you (?:have )?won|you are (?:a |the )?(?:(?:sweepstakes?|lottery|raffle|"
    r"cash draw|grand prize) )?winner|selected as (?:a |the )?winner|"
    r"chosen as (?:a |the )?winner|winning notification|claim (?:your|the) (?:prize|award|"
    r"reward|jackpot|grand prize|(?:lottery )?winnings?)|collect (?:your|the) (?:prize|award|"
    r"reward|grand prize|(?:lottery )?winnings?)|(?:you were )?selected by email ballot"
    r"(?: for (?:a |the )?(?:prize|award|reward|lottery|sweepstakes?))?)\b",
    re.I,
)
_INHERITANCE_CLAIM_RE = re.compile(
    r"\b(?:named as (?:a |the )?beneficiary|selected (?:you )?as (?:a |the )?beneficiary|"
    r"claim (?:your|the) inheritance|release (?:your|the) inheritance|transfer (?:the )?estate|"
    r"receive (?:the )?(?:unclaimed )?estate funds?|share (?:the )?inheritance|unclaimed inheritance)\b",
    re.I,
)
_ADVANCE_FEE_RE = re.compile(
    r"\b(?:processing|release|claim|transfer|courier|delivery|administration|administrative|"
    r"legal|notary|clearance|customs|insurance|registration|handling|inheritance|tax) fee\b"
    r"|\b(?:pay|send|transfer)\b.{0,100}\b(?:tax|fee|charge|deposit)\b.{0,120}"
    r"\b(?:prize|award|reward|jackpot|lottery|winnings?|inheritance|estate|funds?)\b"
    r"|\b(?:prize|award|reward|jackpot|lottery|winnings?|inheritance|estate|funds?)\b.{0,120}"
    r"\b(?:pay|send|transfer)\b.{0,100}\b(?:tax|fee|charge|deposit)\b",
    re.I | re.S,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift card|prepaid card|bitcoin|cryptocurrency|crypto wallet|wire transfer|"
    r"western union|moneygram|money transfer)\b",
    re.I,
)
_SENSITIVE_RE = re.compile(
    r"\b(?:bank account|bank details?|banking details?|routing number|card number|credit card details?|"
    r"passport copy|passport number|social security number|tax identification number|"
    r"identity document|government id)\b",
    re.I,
)
_SECRECY_RE = re.compile(
    r"\b(?:keep (?:this|the matter) secret|strictly confidential|do not tell anyone|"
    r"do not contact the bank|do not contact the lottery|confidential transaction|"
    r"private arrangement)\b",
    re.I,
)
_NO_ENTRY_RE = re.compile(
    r"\b(?:without entering|even though you did not enter|no ticket required|"
    r"you were selected by email ballot|random email selection|email address was selected)\b",
    re.I,
)
_EXECUTOR_RE = re.compile(
    r"\b(?:barrister|foreign lawyer|estate agent|claims? agent|lottery agent|"
    r"fund administrator|executor of (?:an|the) estate)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|lottery results|raffle results|fundraiser raffle)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:prize scam|lottery scam|sweepstakes scam|inheritance scam|advance-fee lottery|"
    r"fake prize|fake inheritance|fraudulent winnings)\b",
    re.I,
)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "prize_scam_detected", "lottery_scam_detected", "inheritance_scam_detected",
        "sweepstakes_scam_detected", "advance_fee_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("prize_analysis", "lottery_analysis", "inheritance_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value):
            return f"scanner prize/lottery/inheritance evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = str(value or "")
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    prize = bool(_PRIZE_RE.search(text))
    inheritance = bool(_INHERITANCE_RE.search(text))
    win_claim = bool(_WIN_CLAIM_RE.search(text))
    inheritance_claim = bool(_INHERITANCE_CLAIM_RE.search(text))
    fee = bool(_ADVANCE_FEE_RE.search(text))
    if prize and win_claim and fee:
        return "prize or lottery winnings require an advance fee or tax"
    if inheritance and inheritance_claim and fee:
        return "inheritance or estate funds require an advance release fee"
    if prize and win_claim and _UNUSUAL_PAYMENT_RE.search(text):
        return "prize claim requests an irreversible payment method"
    if inheritance and inheritance_claim and _UNUSUAL_PAYMENT_RE.search(text):
        return "inheritance claim requests an irreversible payment method"
    if prize and win_claim and _SENSITIVE_RE.search(text) and (_NO_ENTRY_RE.search(text) or _SECRECY_RE.search(text)):
        return "unsolicited prize claim requests sensitive identity or financial data"
    if inheritance and inheritance_claim and _SENSITIVE_RE.search(text) and (
        _SECRECY_RE.search(text) or _EXECUTOR_RE.search(text)
    ):
        return "unexpected inheritance claim requests sensitive data under secrecy or foreign-agent context"
    if prize and win_claim and _NO_ENTRY_RE.search(text) and _SECRECY_RE.search(text):
        return "unentered lottery or prize claim demands secrecy"
    if inheritance and inheritance_claim and _EXECUTOR_RE.search(text) and _SECRECY_RE.search(text):
        return "unexpected estate beneficiary approach demands secrecy"
    return ""


def evaluate_prize_lottery_inheritance_scam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type3-prize-lottery-inheritance",
        points=100,
        reason=f"Prize, lottery, or inheritance scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="prize-lottery-inheritance-scam",
    )]
