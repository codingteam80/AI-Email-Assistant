"""Spam Type 2: classify unwanted mail repeated by the same sender."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:repetitive sender spam|repeated unwanted sender|sender-frequency spam|"
    r"duplicate sender campaign)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|not unwanted|solicited|subscribed newsletter|expected notification|"
    r"transactional message|active conversation|sender allowlisted|trusted sender|false positive|"
    r"security awareness|training|simulation|example|analysis)\b",
    re.I,
)
_UNWANTED_VALUES = {"spam", "unwanted", "junk", "block sender", "blocked sender", "report spam"}
_DELIVERED_REPETITION_SUBJECT_RE = re.compile(
    r"\b(?:weekly bulletin|another follow-up from weekly bulletin|"
    r"more from the weekly bulletin series|your next weekly bulletin)\b",
    re.I,
)
_DELIVERED_REPETITION_BODY_RE = re.compile(
    r"\b(?:this week'?s bulletin|following up with another bulletin|another bulletin|"
    r"recurring bulletin|continuing the bulletin series|next bulletin in this series|"
    r"another planning suggestion|follow-up bulletin|recurring series|another reminder|"
    r"repeated bulletin update|following up again|continuing this update series|"
    r"one more reminder in the recurring bulletin|latest follow-up repeats)\b",
    re.I,
)


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _numeric(email_data: Mapping, *keys: str) -> int:
    for key in keys:
        value = email_data.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _explicit_unwanted(email_data: Mapping) -> bool:
    if any(_true(email_data.get(key)) for key in (
        "user_reported_spam", "user_marked_unwanted", "sender_blocked",
    )):
        return True
    feedback = str(email_data.get("user_feedback") or email_data.get("spam_feedback") or "").casefold().strip()
    return feedback in _UNWANTED_VALUES


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "repetitive_sender_spam_detected", "sender_frequency_spam_detected",
        "duplicate_sender_campaign_detected", "repeated_unwanted_sender_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    classification = str(email_data.get("spam_classification") or "").strip()
    if classification and not _CLEAN_RE.search(classification) and _ANALYSIS_RE.search(classification):
        return f"scanner classification: {classification[:120]}"
    for key in ("spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner repetition evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "user_feedback", "spam_feedback", "classification_analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    sender_count = _numeric(
        email_data, "sender_message_count", "recent_sender_message_count",
        "sender_occurrence_count", "messages_from_sender_24h",
    )
    fingerprint_count = _numeric(
        email_data, "message_fingerprint_count", "duplicate_message_count",
        "similar_message_count",
    )
    repetition = _true(email_data.get("sender_repetition_detected")) or sender_count >= 3 or fingerprint_count >= 3
    if _explicit_unwanted(email_data) and repetition and sender_count >= 2:
        detail = f"{sender_count} recent messages from the sender"
        if fingerprint_count:
            detail += f" with {fingerprint_count} matching or similar messages"
        return detail
    return ""


def _delivered_content_reason(email_data: Mapping, text: str) -> str:
    """Recognize explicit recurring-series language present after Outlook sync."""
    subject = str(email_data.get("subject") or "")
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    if _DELIVERED_REPETITION_SUBJECT_RE.search(subject) and _DELIVERED_REPETITION_BODY_RE.search(text):
        return "delivered message explicitly identifies an ongoing repetitive sender series"
    return ""


def evaluate_repetitive_sender_spam_rules(
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
        rule_id="spam-type2-repetitive-sender",
        points=100,
        reason=f"Repetitive sender spam detected ({reason})",
        categories=("Spam",),
        strong_flag="repetitive-sender-spam",
    )]
