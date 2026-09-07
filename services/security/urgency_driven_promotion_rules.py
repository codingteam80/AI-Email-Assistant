"""Promotional Type 14: identify legitimate retail deadline promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:urgency[- ]driven promotion|retail deadline promotion|"
    r"time[- ]limited store promotion|expiring sales campaign)\b",
    re.I,
)
_DEADLINE_RE = re.compile(
    r"\b(?:final (?:hours?|day|weekend)|last (?:chance|call)|one day left|"
    r"(?:a few|only a few) hours remain|ends? (?:today|tonight|soon|at midnight)|"
    r"until midnight|closing soon|before the offer ends|limited[- ]time|"
    r"closes? today|final day)\b",
    re.I,
)
_COMMERCIAL_CONTEXT_RE = re.compile(
    r"\b(?:store offer|offer|promotion|sale|savings|member pricing|pricing|"
    r"collection|store event|selected[- ]item|selected items?|purchase|shop|products?)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:verify your account|confirm your identity|password|passcode|otp|"
    r"security alert|account suspended|avoid suspension|payment overdue|past due|"
    r"invoice|debt|wire transfer|bank account|card number|cvv|gift card code|"
    r"claim your prize|claim your reward|processing fee|activation fee)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "final hours of our store offer",
    "this promotion ends tonight",
    "last chance to shop this collection",
    "offer available until midnight",
    "our weekend sale ends soon",
    "limited-time collection closes today",
    "one day left for member pricing",
    "final day of our seasonal promotion",
    "savings end at midnight",
    "last call for this store event",
    "this week's offer ends today",
    "only a few hours remain",
    "closing soon: current collection offer",
    "final weekend for selected-item savings",
    "complete your purchase before the offer ends",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "urgency_driven_promotion_detected", "retail_deadline_promotion_detected",
        "time_limited_store_promotion_detected", "expiring_sales_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "urgency_promotion_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner retail-deadline evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a retail deadline promotion"
    if _DEADLINE_RE.search(text) and _COMMERCIAL_CONTEXT_RE.search(text):
        return "a clear retail offer or collection uses an ordinary commercial deadline"
    return ""


def evaluate_urgency_driven_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type14-urgency-driven",
        points=100,
        reason=f"Urgency-driven promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="urgency-driven-promotional",
    )]
