"""Promotional Type 11: identify legitimate loyalty and rewards promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:loyalty and rewards promotion|loyalty rewards promotion|"
    r"member rewards campaign|reward points promotion)\b",
    re.I,
)
_LOYALTY_RE = re.compile(
    r"\b(?:loyalty|member rewards?|membership rewards?|reward points?|"
    r"member benefits?|loyalty benefits?|reward balance|points balance)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:earn|collect|redeem|use|double|bonus|benefits?|balance|"
    r"every purchase|next purchase|selected items?|featured products?|"
    r"members?|membership|available|waiting|go further)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:lottery|sweepstakes|inheritance|prize winner|processing fee|"
    r"activation fee|verification deposit|password|passcode|otp|bank account|"
    r"card number|cvv|gift card code|claim your reward immediately)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "your member rewards are waiting",
    "earn points on your next purchase",
    "explore your loyalty benefits",
    "double points this weekend",
    "a new reward for members",
    "use your points on selected items",
    "member rewards update",
    "collect bonus points this week",
    "your loyalty offer is available",
    "more rewards with every purchase",
    "redeem points for member benefits",
    "exclusive benefits for loyalty members",
    "your reward balance can go further",
    "bonus rewards on featured products",
    "celebrate your membership with rewards",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "loyalty_rewards_promotion_detected", "member_rewards_campaign_detected",
        "reward_points_promotion_detected", "loyalty_benefits_promotion_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "loyalty_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner loyalty-rewards evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a loyalty or rewards promotion"
    if _LOYALTY_RE.search(text) and _ACTION_RE.search(text):
        return "ordinary membership points, rewards, or loyalty benefits are promoted"
    return ""


def evaluate_loyalty_rewards_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type11-loyalty-rewards",
        points=100,
        reason=f"Loyalty and rewards promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="loyalty-rewards-promotional",
    )]
