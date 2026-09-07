"""Scam/Fraud Type 6: detect fake refunds and recovery services."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_RECOVERY_RE = re.compile(
    r"\b(?:refund|reimbursement|chargeback|asset recovery|fund recovery|recovery service|"
    r"recovery agent|recovery company|refund service|chargeback specialist|recover(?:ed|ing)? "
    r"(?:your |the )?(?:money|funds?|assets?|loss(?:es)?|bitcoin|crypto(?:currency)?)|"
    r"retrieve (?:your |the )?(?:money|funds?|assets?)|lost funds?|stolen funds?|scam losses?|"
    r"investment losses?)\b",
    re.I,
)
_REFUND_LURE_RE = re.compile(
    r"\b(?:refund|reimbursement|chargeback)\b.{0,100}\b(?:approved|available|authorized|due|owed|"
    r"pending|ready|released?|recover(?:ed|y)?|claim|collect|receive|transfer)\b"
    r"|\b(?:claim|collect|receive|release|unlock)\b.{0,80}\b(?:refund|reimbursement|chargeback)\b",
    re.I | re.S,
)
_FEE_RE = re.compile(
    r"\b(?:upfront|advance|initial) (?:fee|payment|deposit|retainer|charge)\b"
    r"|\b(?:processing|activation|release|recovery|registration|verification|network|gas|legal|"
    r"tax|transfer|administration|handling|service|security) (?:fee|charge|deposit)\b"
    r"|\b(?:fee|deposit|retainer|charge) (?:first|upfront|in advance)\b",
    re.I,
)
_PAY_RE = re.compile(
    r"\b(?:pay|pays|paying|paid|send|sends|sending|sent|transfer|transfers|transferring|"
    r"transferred|wire|wires|wiring|wired|buy|buys|buying|bought|purchase|purchases|"
    r"purchasing|purchased|provide|provides|providing|provided)\b.{0,110}"
    r"\b(?:fee|charge|deposit|retainer|tax|payment|gift[- ]card|prepaid (?:card|voucher)|"
    r"bitcoin|cryptocurrency|crypto|money transfer)\b",
    re.I | re.S,
)
_BEFORE_RELEASE_RE = re.compile(
    r"\b(?:before|prior to)\b.{0,100}\b(?:refund|reimburse|recover|release|return|send|sent|"
    r"transfer|unlock|receive|process|start|open)\w*"
    r"|\b(?:to|in order to)\b.{0,50}\b(?:release|unlock|receive|recover|transfer|process)\w*"
    r"|\b(?:after (?:the )?(?:fee|deposit|payment) (?:is )?paid|fee first|payment first)\b",
    re.I | re.S,
)
_GUARANTEE_RE = re.compile(
    r"\b(?:guaranteed (?:refund|recovery|chargeback|success)|guarantees? (?:your |the )?"
    r"(?:refund|recovery|chargeback)|100% (?:refund|recovery|success)|"
    r"full recovery guaranteed|funds? (?:have been |already )?(?:located|recovered)|"
    r"recovery assured|refund guaranteed)\b",
    re.I,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"western union|moneygram|money transfer|friends and family|personal account)\b",
    re.I,
)
_SENSITIVE_ACCESS_RE = re.compile(
    r"\b(?:seed phrase|recovery phrase|private key|wallet password|wallet credentials?|"
    r"bank login|banking password|account password|one[- ]time passcode|otp|security code)\b",
    re.I,
)
_REMOTE_ACCESS_RE = re.compile(
    r"\b(?:remote access|remote desktop|screen sharing|screen-share|install (?:a |the )?"
    r"(?:support|remote) (?:app|tool|software)|anydesk|teamviewer|quick assist)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:fake refund|refund scam|refund fraud|recovery scam|fund recovery scam|"
    r"asset recovery scam|chargeback scam|fraudulent recovery service)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|fraud prevention|returned to (?:the )?original payment method|"
    r"refunded to (?:the )?original card|no fee (?:is )?required|no action (?:is )?required|"
    r"will never request|never asks? for)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake refund|refund scam|recovery service scam|fund recovery fraud|"
    r"asset recovery scam|chargeback scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "fake_refund_detected", "refund_scam_detected", "recovery_scam_detected",
        "fake_recovery_service_detected", "fund_recovery_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("refund_analysis", "recovery_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner fake-refund/recovery evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes a fake refund or recovery service"
    recovery = bool(_RECOVERY_RE.search(text))
    refund_lure = bool(_REFUND_LURE_RE.search(text))
    fee = bool(_FEE_RE.search(text))
    payment = bool(_PAY_RE.search(text))
    before_release = bool(_BEFORE_RELEASE_RE.search(text))
    guarantee = bool(_GUARANTEE_RE.search(text))
    unusual = bool(_UNUSUAL_PAYMENT_RE.search(text))
    if recovery and _SENSITIVE_ACCESS_RE.search(text):
        return "recovery service requests wallet, banking, or authentication secrets"
    if recovery and _REMOTE_ACCESS_RE.search(text) and (payment or guarantee):
        return "refund or recovery lure requests remote device access"
    if recovery and fee and payment and (guarantee or unusual or before_release):
        return "refund or recovery is conditioned on a deceptive advance payment"
    if refund_lure and fee and payment and before_release and (unusual or guarantee):
        return "promised refund requires an irreversible fee before release"
    if recovery and guarantee and unusual:
        return "guaranteed recovery uses an irreversible payment channel"
    return ""


def evaluate_fake_refund_recovery_service_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type6-fake-refund-recovery",
        points=100,
        reason=f"Fake refund or recovery service detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="fake-refund-recovery-service",
    )]
