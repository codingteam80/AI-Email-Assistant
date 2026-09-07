"""Promotional Type 17: identify excessively intrusive promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:excessively intrusive promotion|intrusive behavioral promotion|"
    r"persistent tracking promotion|overly invasive marketing campaign)\b",
    re.I,
)
_INTRUSIVE_RE = re.compile(
    r"\b(?:keep noticing|keep tailoring|we (?:are )?still following|"
    r"we (?:saw|noticed|tracked|recorded) (?:you|your|each|every)|"
    r"tracks? your|following your|persistent recommendations?|"
    r"repeated (?:product )?(?:clicks?|views?|visits?)|every recent visit|each return|"
    r"browsing (?:history|activity)|click activity|shopping behavior|store behavior|"
    r"product activity|activity[- ]based)\b",
    re.I,
)
_PROMOTIONAL_CONTEXT_RE = re.compile(
    r"\b(?:promotion|offer|offers|products?|collection|recommendations?|"
    r"campaign|store|shopping|picks?|tailoring)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:security monitoring|security activity|incident monitoring|"
    r"employee monitoring|workplace monitoring|law enforcement|location tracking|"
    r"package tracking|tracking number|delivery status|verify your account|"
    r"confirm your identity|password|passcode|otp|account suspended|"
    r"payment overdue|invoice|wire transfer|bank account|card number|cvv|"
    r"gift card code|processing fee)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "we keep noticing your store visits",
    "this offer follows your browsing activity",
    "we saw you view these products again",
    "a promotion based on repeated clicks",
    "your shopping behavior shaped this offer",
    "we are still following your product interest",
    "more offers based on every recent visit",
    "this campaign tracks your viewed items",
    "we noticed each return to this collection",
    "your click activity inspired this promotion",
    "another offer from your browsing history",
    "we used your recent store behavior",
    "persistent recommendations from your activity",
    "this promotion reflects repeated product views",
    "we keep tailoring offers from your visits",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "excessively_intrusive_promotion_detected",
        "intrusive_behavioral_promotion_detected",
        "persistent_tracking_promotion_detected",
        "invasive_marketing_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "intrusive_promotion_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner intrusive-promotion evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies an excessively intrusive promotion"
    if _INTRUSIVE_RE.search(text) and _PROMOTIONAL_CONTEXT_RE.search(text):
        return "marketing explicitly relies on persistent or repeated behavioral observation"
    return ""


def evaluate_excessively_intrusive_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type17-excessively-intrusive",
        points=100,
        reason=f"Excessively intrusive promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="excessively-intrusive-promotional",
    )]
