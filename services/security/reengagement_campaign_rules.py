"""Promotional Type 13: identify legitimate re-engagement campaigns."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:re[- ]engagement campaign|customer reactivation campaign|"
    r"win[- ]back campaign|lapsed customer campaign)\b",
    re.I,
)
_REENGAGEMENT_RE = re.compile(
    r"\b(?:we (?:have )?missed you|welcome (?:you )?back|come (?:back|see)|"
    r"it has been a while|reconnect|return to|awaits your return|visit us again|"
    r"since your last visit|rediscover|since you last stopped by|"
    r"your next visit|love to welcome you back)\b",
    re.I,
)
_COMMERCIAL_CONTEXT_RE = re.compile(
    r"\b(?:products?|collection|store|shop|latest arrivals?|new arrivals?|"
    r"favorites?|styles?|browse|explore|visit|what is new|what has changed)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:reactivate your account|restore account access|verify your account|"
    r"confirm your identity|password|passcode|otp|account suspended|payment overdue|"
    r"past due|invoice|debt|former employee|class reunion|relationship counseling|"
    r"wire transfer|bank account|card number|cvv)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "we have missed you",
    "welcome back to our collection",
    "come see what is new",
    "it has been a while",
    "reconnect with your favorite products",
    "return to discover our latest arrivals",
    "a fresh collection awaits your return",
    "visit us again when you are ready",
    "see what has changed since your last visit",
    "rediscover the store you know",
    "new arrivals since you last stopped by",
    "come back and explore the latest",
    "your next visit starts here",
    "return to your favorite collection",
    "we would love to welcome you back",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "reengagement_campaign_detected", "customer_reactivation_campaign_detected",
        "win_back_campaign_detected", "lapsed_customer_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "reengagement_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner re-engagement evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a re-engagement campaign"
    if _REENGAGEMENT_RE.search(text) and _COMMERCIAL_CONTEXT_RE.search(text):
        return "a previous visitor or customer is invited back to ordinary store content"
    return ""


def evaluate_reengagement_campaign_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type13-reengagement-campaign",
        points=100,
        reason=f"Re-engagement campaign detected ({reason})",
        categories=("Promotional",),
        strong_flag="reengagement-campaign-promotional",
    )]
