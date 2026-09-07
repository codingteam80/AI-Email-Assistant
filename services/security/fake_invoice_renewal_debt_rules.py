"""Scam/Fraud Type 5: detect fake invoices, renewals, and debts."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_BILLING_RE = re.compile(
    r"\b(?:invoice|bill|billing statement|statement|purchase order|renewal|auto[- ]?renewal|"
    r"subscription|license|service plan|maintenance plan|warranty|membership|domain|hosting|"
    r"antivirus|security package|debt|balance|amount due|arrears|past-due account|collection notice|"
    r"collections account|settlement demand)\b",
    re.I,
)
_EXPLICIT_FAKE_RE = re.compile(
    r"\b(?:fake|bogus|fraudulent|fabricated|forged|false|fictitious|nonexistent|non-existent|"
    r"unauthorized|unrecognised|unrecognized|unsolicited|sham)\b.{0,100}\b(?:invoice|bill|"
    r"statement|purchase order|renewal|subscription|license|service plan|warranty|membership|"
    r"domain|hosting|debt|balance|collection|settlement)\b"
    r"|\b(?:invoice|bill|statement|purchase order|renewal|subscription|license|service plan|"
    r"warranty|membership|domain|hosting|debt|balance|collection|settlement)\b.{0,100}"
    r"\b(?:is|was|are|were)?\s*(?:fake|bogus|fraudulent|fabricated|forged|false|fictitious|"
    r"nonexistent|non-existent|unauthorized|unrecognised|unrecognized|unsolicited|sham)\b",
    re.I | re.S,
)
_NO_RELATION_RE = re.compile(
    r"\b(?:never ordered|did not order|didn't order|no such order|no account|do not have an account|"
    r"never subscribed|did not subscribe|didn't subscribe|not your debt|debt you do not owe|"
    r"unknown account|unrecognized charge|unauthorized charge)\b",
    re.I,
)
_PAYMENT_RE = re.compile(
    r"\b(?:pay|settle|remit|send|transfer|wire|submit payment|make payment|amount due|balance due)\b",
    re.I,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]card|prepaid (?:card|voucher)|bitcoin|cryptocurrency|crypto wallet|"
    r"western union|moneygram|money transfer|friends and family|personal account)\b",
    re.I,
)
_THREAT_RE = re.compile(
    r"\b(?:final notice|past due|overdue|delinquent|pay immediately|due today|within (?:24|48) hours|"
    r"suspend|suspension|terminate|termination|disconnect|service interruption|legal action|"
    r"court action|wage garnishment|asset seizure|arrest|refer(?:red)? to collections?)\b",
    re.I,
)
_REDIRECT_RE = re.compile(
    r"\b(?:new bank details|updated bank details|changed bank account|replacement account|"
    r"different bank account|personal account|disregard (?:the )?(?:previous|old) (?:invoice|"
    r"payment instructions?|bank details)|do not use (?:the )?(?:old|previous) account|"
    r"pay outside (?:the )?(?:portal|platform)|bypass (?:the )?(?:billing portal|payment portal))\b",
    re.I,
)
_AUTO_RENEWAL_RE = re.compile(
    r"\b(?:auto[- ]?renew(?:ed|al)|automatically renewed|renewal (?:was )?(?:processed|completed)|"
    r"subscription (?:was )?renewed|charged for (?:a |the )?renewal)\b",
    re.I,
)
_CALL_CANCEL_RE = re.compile(
    r"\b(?:call|phone|contact)\b.{0,80}\b(?:cancel|refund|reverse|dispute|stop (?:the )?renewal)\b"
    r"|\b(?:cancel|refund|reverse|dispute)\b.{0,80}\b(?:call|phone|contact)\b",
    re.I | re.S,
)
_AMOUNT_RE = re.compile(r"(?:[$€£]\s?\d{2,}(?:[,.]\d{2})?|\b\d{2,}(?:[,.]\d{2})?\s?(?:usd|eur|gbp|dollars?|euros?|pounds?))", re.I)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|fraud prevention|invoice fraud awareness)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake invoice|invoice fraud|renewal scam|subscription renewal scam|fake debt|"
    r"debt collection scam|fraudulent billing|payment redirection fraud)\b",
    re.I,
)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "fake_invoice_detected", "fake_renewal_detected", "fake_debt_detected",
        "invoice_fraud_detected", "renewal_scam_detected", "debt_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("invoice_analysis", "renewal_analysis", "debt_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_FAKE_RE.search(value):
            return f"scanner fake-billing evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = str(value or "")
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    billing = bool(_BILLING_RE.search(text))
    payment = bool(_PAYMENT_RE.search(text))
    if _EXPLICIT_FAKE_RE.search(text):
        return "invoice, renewal, subscription, or debt is explicitly fake or unauthorized"
    if billing and payment and _REDIRECT_RE.search(text):
        return "billing payment is redirected to replacement or personal account details"
    if billing and payment and _UNUSUAL_PAYMENT_RE.search(text) and _THREAT_RE.search(text):
        return "invoice or debt demand combines coercive pressure with irreversible payment"
    if billing and _NO_RELATION_RE.search(text) and (payment or _THREAT_RE.search(text)):
        return "payment is demanded for an order, subscription, account, or debt with no relationship"
    if billing and _AUTO_RENEWAL_RE.search(text) and _CALL_CANCEL_RE.search(text) and _AMOUNT_RE.search(text):
        return "unexpected high-value renewal directs the recipient to call for cancellation or refund"
    return ""


def evaluate_fake_invoice_renewal_debt_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type5-fake-invoice-renewal-debt",
        points=100,
        reason=f"Fake invoice, renewal, or debt detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="fake-invoice-renewal-debt",
    )]
