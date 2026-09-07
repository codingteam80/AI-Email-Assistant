"""Scam/Fraud Type 11: detect payment-diversion fraud."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_PAYMENT_CONTEXT_RE = re.compile(
    r"\b(?:vendor|supplier|contractor|invoice|purchase order|accounts payable|remittance|payment|"
    r"payroll|salary|direct deposit|rent|landlord|real estate|property closing|closing|escrow|"
    r"settlement|deposit|shipping|freight|insurance|beneficiary|subscription)\b",
    re.I,
)
_CHANGE_RE = re.compile(
    r"\b(?:new|updated|revised|changed|replacement|alternate|alternative|different|corrected|"
    r"temporary|personal|third[- ]party)\b.{0,80}\b(?:bank|account|banking|beneficiary|routing|"
    r"wire|payment|remittance|deposit)\b"
    r"|\b(?:bank|account|banking|beneficiary|routing|wire|payment|remittance|deposit)\b.{0,80}"
    r"\b(?:has changed|was changed|were changed|is now|use instead|replacement|alternate|revised|updated)\b",
    re.I | re.S,
)
_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:pay|send|transfer|wire|remit|route|reroute|redirect|deposit|update|change|switch|"
    r"replace|amend)\b.{0,140}\b(?:invoice|balance|funds?|money|payment|wire|remittance|salary|"
    r"payroll|direct deposit|rent|deposit|beneficiary|bank|account|details?|instructions?)\b"
    r"|\b(?:invoice|balance|funds?|payment|salary|payroll|direct deposit|rent|escrow|settlement)\b"
    r".{0,120}\b(?:to|into|using|via)\b.{0,70}\b(?:account|beneficiary|bank|wire details?)\b",
    re.I | re.S,
)
_NEW_DESTINATION_RE = re.compile(
    r"\b(?:new|updated|revised|changed|replacement|alternate|alternative|different|temporary|"
    r"personal|third[- ]party)\s+(?:bank )?(?:account|beneficiary|wire instructions?|payment details?|"
    r"bank details?|routing details?|deposit account)\b"
    r"|\b(?:outside|bypass) (?:the )?(?:vendor|billing|payment|payroll) portal\b"
    r"|\b(?:disregard|ignore|do not use|don't use) (?:the )?(?:old|previous|original) "
    r"(?:account|bank details?|payment instructions?|wire instructions?)\b",
    re.I,
)
_DIVERSION_CONTEXT_RE = re.compile(
    r"\b(?:disregard|ignore|do not use|don't use|mailbox (?:issue|problem)|banking (?:issue|problem)|"
    r"account (?:issue|problem|audit)|confidential|do not call|don't call|no need to verify|"
    r"without calling|immediately|urgent|today|before closing|before cutoff)\b",
    re.I,
)
_EXECUTIVE_RE = re.compile(r"\b(?:ceo|cfo|president|director|executive|owner|boss)\b", re.I)
_EXPLICIT_RE = re.compile(
    r"\b(?:payment[- ]diversion fraud|payment redirection fraud|changed[- ]bank[- ]detail fraud|"
    r"bank detail change scam|bec payment diversion|business email compromise payment|"
    r"payroll diversion fraud|wire redirection scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|unchanged bank details|verified vendor portal|"
    r"authenticated hr portal|confirmed (?:by|through) (?:a )?(?:known|trusted|verified) (?:phone|number|"
    r"channel|contact)|confirmed in person|dual approval completed|no change to (?:the )?payment details|"
    r"original payment method)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:payment[- ]diversion fraud|changed[- ]bank[- ]detail fraud|bec payment redirection|"
    r"payroll diversion|wire redirection fraud|vendor payment diversion)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "payment_diversion_detected", "bank_detail_change_fraud_detected",
        "bec_payment_diversion_detected", "payroll_diversion_detected",
        "wire_redirection_fraud_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("payment_analysis", "bank_detail_analysis", "bec_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner payment-diversion evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes payment-diversion fraud"
    context = bool(_PAYMENT_CONTEXT_RE.search(text))
    changed = bool(_CHANGE_RE.search(text))
    action = bool(_PAYMENT_ACTION_RE.search(text))
    destination = bool(_NEW_DESTINATION_RE.search(text))
    diversion = bool(_DIVERSION_CONTEXT_RE.search(text))
    executive = bool(_EXECUTIVE_RE.search(text))
    if context and changed and action and destination:
        return "an established payment is redirected to changed or replacement destination details"
    if context and destination and action and diversion:
        return "payment instructions bypass prior details or verification and redirect the funds"
    if executive and action and destination and diversion:
        return "an alleged executive confidentially redirects a payment to an alternate beneficiary"
    return ""


def evaluate_payment_diversion_fraud_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type11-payment-diversion",
        points=100,
        reason=f"Payment-diversion fraud detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="payment-diversion-fraud",
    )]
