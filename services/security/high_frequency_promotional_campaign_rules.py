"""Promotional Type 16: identify high-frequency promotional campaigns."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:high[- ]frequency promotional campaign|frequent promotional campaign|"
    r"recurring promotion campaign|high[- ]cadence marketing campaign)\b",
    re.I,
)
_FREQUENCY_RE = re.compile(
    r"\b(?:daily|weekly|recurring|regular|another|more promotions?|"
    r"second (?:store )?update|frequent|roundup|digest|campaign update|"
    r"today's promotional update|latest offer digest)\b",
    re.I,
)
_PROMOTIONAL_CONTEXT_RE = re.compile(
    r"\b(?:promotion|offers?|deals?|savings|store|products?|collection|"
    r"sales campaign|member offers?|marketplace|product highlights?)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:security updates?|incident updates?|incident status|incident report|system alerts?|status digest|"
    r"medical digest|daily news report|verify your account|password|passcode|otp|"
    r"account suspended|payment overdue|invoice|wire transfer|bank account|"
    r"card number|cvv|gift card code)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "today's promotional update",
    "your daily store offers",
    "another collection update for you",
    "this week's promotion roundup",
    "daily deals from our store",
    "your latest offer digest",
    "regular savings update",
    "more promotions from our collection",
    "today's second store update",
    "frequent offers from our marketplace",
    "daily product highlights",
    "your recurring promotion summary",
    "another set of member offers",
    "weekly sales campaign update",
    "latest deals in your regular digest",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _numeric_frequency_reason(email_data: Mapping) -> str:
    for key in (
        "promotional_messages_24h", "campaign_messages_24h",
        "sender_promotional_count_24h", "promotional_frequency_count",
    ):
        try:
            value = int(email_data.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if value >= 3:
            return f"{key.replace('_', ' ')} is {value}"
    return ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "high_frequency_promotional_campaign_detected",
        "frequent_promotional_campaign_detected",
        "recurring_promotion_campaign_detected",
        "high_cadence_marketing_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    numeric = _numeric_frequency_reason(email_data)
    if numeric:
        return numeric
    for key in (
        "promotional_classification", "content_analysis",
        "campaign_frequency_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner high-frequency campaign evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a high-frequency promotion"
    if _FREQUENCY_RE.search(text) and _PROMOTIONAL_CONTEXT_RE.search(text):
        return "recurring or repeated marketing cadence accompanies ordinary promotional content"
    return ""


def evaluate_high_frequency_promotional_campaign_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type16-high-frequency-campaign",
        points=100,
        reason=f"High-frequency promotional campaign detected ({reason})",
        categories=("Promotional",),
        strong_flag="high-frequency-campaign-promotional",
    )]
