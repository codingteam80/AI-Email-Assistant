"""Scam/Fraud Type 4: detect advance-fee schemes."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_BENEFIT_RE = re.compile(
    r"\b(?:loan|credit|grant|funding|investment|profit|return|job|employment|position|contract|"
    r"visa|permit|immigration|travel document|parcel|package|shipment|delivery|refund|"
    r"reimbursement|compensation|benefit|relief payment|funds?|payout|transfer|donation|"
    r"charity funding|business opportunity|commission|settlement|award|procurement)\b",
    re.I,
)
_FEE_RE = re.compile(
    r"\b(?:processing|application|registration|administration|administrative|activation|release|"
    r"clearance|customs|courier|delivery|insurance|legal|notary|verification|onboarding|handling|"
    r"transfer|transaction|security|commitment|membership|documentation|tax|service) (?:fee|charge)\b"
    r"|\b(?:upfront|advance|initial) (?:fee|payment|deposit|charge)\b"
    r"|\b(?:fee|deposit|charge) (?:upfront|in advance|first)\b",
    re.I,
)
_PAY_RE = re.compile(
    r"\b(?:pay|pays|paying|paid|send|sends|sending|sent|transfer|transfers|transferring|"
    r"transferred|remit|remits|remitting|remitted|wire|wires|wiring|wired|submit|submits|"
    r"submitting|submitted|provide|provides|providing|provided|purchase|purchases|purchasing|"
    r"purchased|buy|buys|buying|bought)\b.{0,100}"
    r"\b(?:fee|charge|deposit|tax|payment|gift[- ]card|prepaid (?:card|voucher)|bitcoin|"
    r"cryptocurrency|crypto|money transfer)\b",
    re.I | re.S,
)
_BEFORE_BENEFIT_RE = re.compile(
    r"\b(?:before|prior to)\b.{0,100}\b(?:approv\w*|process\w*|releas\w*|receiv\w*|send|sent|"
    r"deliver\w*|transfer\w*|unlock\w*|start\w*|begin\w*|began|issue\w*|secur\w*|confirm\w*|"
    r"disburs\w*|award\w*)"
    r"|\b(?:to|in order to)\b.{0,50}\b(?:approv\w*|process\w*|releas\w*|receiv\w*|"
    r"unlock\w*|secur\w*|disburs\w*)"
    r"|\b(?:fee first|pay first|payment first|after (?:the )?(?:fee|deposit|payment) (?:is )?paid)\b",
    re.I | re.S,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]card|prepaid (?:card|voucher)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"western union|moneygram|money transfer|friends and family|personal account)\b",
    re.I,
)
_DECEPTION_RE = re.compile(
    r"\b(?:guaranteed approval|guaranteed return|guaranteed profit|no credit check|no interview|"
    r"no paperwork|no documents?|without verification|unverified agent|private arrangement|"
    r"keep (?:this|it) secret|do not tell|act immediately|today only|final opportunity|"
    r"cannot be refunded|non-refundable|irreversible)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:advance[- ]fee scam|advance payment scam|upfront[- ]fee scam|fee-first scheme|"
    r"pay-to-receive scheme|419 scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|fraud prevention|legitimate application fee)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:advance[- ]fee scam|upfront[- ]fee fraud|fee-first fraud|pay-to-receive scam|"
    r"419 scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "advance_fee_scam_detected", "upfront_fee_scam_detected",
        "fee_first_scam_detected", "pay_to_receive_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("advance_fee_analysis", "payment_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value):
            return f"scanner advance-fee evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes an advance-fee fraud scheme"
    benefit = bool(_BENEFIT_RE.search(text))
    fee = bool(_FEE_RE.search(text))
    payment = bool(_PAY_RE.search(text))
    before_benefit = bool(_BEFORE_BENEFIT_RE.search(text))
    unusual = bool(_UNUSUAL_PAYMENT_RE.search(text))
    deceptive = bool(_DECEPTION_RE.search(text))
    if benefit and fee and payment and before_benefit and (unusual or deceptive):
        return "promised funds, service, or opportunity requires a deceptive upfront fee"
    if benefit and fee and payment and unusual:
        return "advance fee for a promised benefit uses an irreversible payment method"
    if benefit and fee and before_benefit and deceptive:
        return "guaranteed or secret benefit is conditioned on payment of an advance fee"
    return ""


def evaluate_advance_fee_scam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type4-advance-fee",
        points=100,
        reason=f"Advance-fee scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="advance-fee-scam",
    )]
