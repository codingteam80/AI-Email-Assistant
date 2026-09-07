"""Scam/Fraud Type 8: detect fake-check and overpayment schemes."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_CHECK_RE = re.compile(
    r"\b(?:check|cheque|cashier'?s check|bank check|certified check|e-check|electronic check|"
    r"digital check|mobile check)\b",
    re.I,
)
_DEPOSIT_RE = re.compile(
    r"\b(?:deposit|mobile deposit|cash|endorse|scan|photograph|submit)\b.{0,100}"
    r"\b(?:check|cheque|e-check|payment)\b"
    r"|\b(?:check|cheque|e-check|payment)\b.{0,100}\b(?:deposit|cash|endorse|scan|submit)\b",
    re.I | re.S,
)
_OVERPAYMENT_RE = re.compile(
    r"\b(?:overpaid|overpayment|over payment|paid too much|paid more than|extra amount|"
    r"(?:the )?excess(?: (?:payment|funds?|amount|money|portion|balance))?|"
    r"surplus (?:payment|funds?|amount|money)|"
    r"remainder|remaining balance|difference|duplicate payment|paid twice|above the price|"
    r"more than the (?:price|invoice|total|amount due))\b",
    re.I,
)
_RETURN_RE = re.compile(
    r"\b(?:refund|return|send back|transfer back|wire back|repay|remit|forward|send|transfer|wire)\b"
    r".{0,120}\b(?:excess|overpayment|surplus|extra|remainder|remaining|difference|balance|portion|"
    r"funds?|money|amount)\b"
    r"|\b(?:excess|overpayment|surplus|extra|remainder|remaining|difference|balance|portion)\b"
    r".{0,120}\b(?:refund|return|send|transfer|wire|repay|remit|forward)\b",
    re.I | re.S,
)
_PURCHASE_RE = re.compile(
    r"\b(?:buy|purchase|pay)\b.{0,120}\b(?:gift[- ]cards?|equipment|computer|laptop|"
    r"software|supplies|shipper|courier|delivery agent|vendor)\b",
    re.I | re.S,
)
_UNUSUAL_DEST_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"western union|moneygram|money transfer|payment app|personal account|different account|"
    r"third-party account|shipper|courier)\b",
    re.I,
)
_CLEARING_PRESSURE_RE = re.compile(
    r"\b(?:before (?:the )?check clears|while (?:the )?check is pending|pending clearance|"
    r"funds? (?:are|will be) available immediately|available balance means cleared|"
    r"do not wait for clearance|send (?:it|the money|the funds) immediately|today|right away|"
    r"as soon as (?:you )?deposit|after (?:the )?mobile deposit)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:fake check|fake cheque|forged check|counterfeit check|bad check scam|"
    r"check overpayment scam|overpayment scam|fraudulent overpayment)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not deposit|do not send|fraud prevention|returned to (?:the )?"
    r"original payment method|refund through (?:the )?original payment method|"
    r"after (?:the )?check fully clears|verified bank correction)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake check scam|check overpayment scam|overpayment fraud|counterfeit check|"
    r"bad check scheme)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "fake_check_detected", "overpayment_scam_detected", "check_scam_detected",
        "counterfeit_check_detected", "fake_cheque_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("check_analysis", "overpayment_analysis", "payment_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner fake-check/overpayment evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "check or overpayment is explicitly fake or fraudulent"
    check = bool(_CHECK_RE.search(text))
    deposit = bool(_DEPOSIT_RE.search(text))
    overpayment = bool(_OVERPAYMENT_RE.search(text))
    returning = bool(_RETURN_RE.search(text))
    purchase = bool(_PURCHASE_RE.search(text))
    unusual = bool(_UNUSUAL_DEST_RE.search(text))
    pressure = bool(_CLEARING_PRESSURE_RE.search(text))
    if check and deposit and overpayment and returning and (unusual or pressure):
        return "check overpayment directs the recipient to return excess funds before final settlement"
    if check and deposit and purchase and (returning or unusual or pressure):
        return "check proceeds must fund third-party purchases or onward transfers"
    if overpayment and returning and unusual and pressure:
        return "alleged overpayment must be urgently returned through a different or irreversible channel"
    if check and overpayment and returning and (unusual or pressure):
        return "recipient must return part of an alleged check overpayment"
    return ""


def evaluate_fake_check_overpayment_scam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type8-fake-check-overpayment",
        points=100,
        reason=f"Fake check or overpayment scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="fake-check-overpayment-scam",
    )]
