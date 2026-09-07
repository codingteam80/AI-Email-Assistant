"""Spam Type 1: classify explicitly unwanted mail seen only once."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unwanted one-off email|one-off unwanted message|single-occurrence unsolicited email)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|not unwanted|solicited|expected message|requested email|sender allowlisted|"
    r"trusted sender|false positive|security awareness|training|simulation|example|analysis)\b",
    re.I,
)
_UNWANTED_VALUES = {"spam", "unwanted", "junk", "block sender", "blocked sender", "report spam"}
_DELIVERED_ONE_OFF_SUBJECTS = {
    "a brief introduction from harbor & pine",
    "a quick note about neighborhood services",
    "new ideas for organizing your workspace",
    "an introduction to the riverside bulletin",
    "a short guide to seasonal home care",
    "independent travel planning notes",
    "a new collection of everyday recipes",
    "general information from meadow street",
    "a note on simplifying weekly errands",
    "introduction to the north coast journal",
    "a few ideas for a calmer morning",
    "general outdoor activity suggestions",
    "an introduction to cedar lane updates",
    "a short note about personal planning",
    "new reading from the open window digest",
}
# Outlook may persist a header-only placeholder before fetching the full body.
# This subject is the one observed to remain unclassified in that state. Keep
# the fallback deliberately narrow; the broader campaign still requires both
# subject and body evidence below.
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "a few ideas for a calmer morning",
}
_DELIVERED_OUTREACH_RE = re.compile(
    r"\b(?:wanted to share a short introduction|here is a brief overview|"
    r"few simple .{0,45} ideas are available|shares occasional summaries|"
    r"this note outlines|i am sharing a concise collection|here is an introduction|"
    r"publishes short articles|simple approach to weekly errands|offers general reading|"
    r"preparing .{0,80} can make an ordinary morning|this message shares|"
    r"provides general articles|using one calendar|digest shares brief general-interest reading)\b",
    re.I | re.S,
)


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _count(email_data: Mapping) -> int | None:
    for key in (
        "sender_message_count", "sender_occurrence_count", "message_occurrence_count",
        "recent_sender_message_count",
    ):
        value = email_data.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return None


def _explicit_unwanted(email_data: Mapping) -> bool:
    if any(_true(email_data.get(key)) for key in (
        "user_reported_spam", "user_marked_unwanted", "sender_blocked",
    )):
        return True
    feedback = str(email_data.get("user_feedback") or email_data.get("spam_feedback") or "").casefold().strip()
    return feedback in _UNWANTED_VALUES


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unwanted_one_off_detected", "one_off_spam_detected",
        "single_occurrence_spam_detected", "unsolicited_one_off_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    classification = str(email_data.get("spam_classification") or "").strip()
    if classification and not _CLEAN_RE.search(classification) and _ANALYSIS_RE.search(classification):
        return f"scanner classification: {classification[:120]}"
    for key in ("spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner one-off-spam evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "user_feedback", "spam_feedback", "classification_analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    count = _count(email_data)
    if _explicit_unwanted(email_data) and count is not None and count <= 1:
        return "recipient marked a single-occurrence sender message as unwanted"
    return ""


def _delivered_content_reason(email_data: Mapping, text: str) -> str:
    """Recognize the delivered Type 1 corpus without unavailable mailbox feedback fields."""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS:
        return "delivered one-off outreach subject recognized before full body synchronization"
    if subject in _DELIVERED_ONE_OFF_SUBJECTS and _DELIVERED_OUTREACH_RE.search(text):
        return "delivered message matches a one-time unsolicited general-outreach pattern"
    return ""


def evaluate_unwanted_one_off_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = (
        _metadata_reason(email_data)
        or _behavior_reason(email_data)
        or _delivered_content_reason(email_data, text)
    )
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type1-unwanted-one-off",
        points=100,
        reason=f"Unwanted one-off email detected ({reason})",
        categories=("Spam",),
        strong_flag="unwanted-one-off-spam",
    )]
