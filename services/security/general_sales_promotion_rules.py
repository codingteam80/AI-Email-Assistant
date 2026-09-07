"""Promotional Type 6: identify legitimate general sales promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:general sales promotion|retail sales email|store promotion|"
    r"seasonal sales campaign)\b",
    re.I,
)
_SALES_RE = re.compile(
    r"\b(?:sale|sales event|special (?:shopping )?offer|store offers?|savings?|save\s+(?:on|more)|"
    r"percent off|% off|lower prices?|member pricing|bundle savings|"
    r"complimentary shipping|free shipping|current deals?)\b",
    re.I,
)
_RETAIL_CONTEXT_RE = re.compile(
    r"\b(?:shop|shopping|store|collection|selected (?:products|items)|products?|"
    r"order|members?|seasonal|weekend|this week|now available|popular items|"
    r"limited[- ]time|explore|enjoy)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:unauthorized promo|stolen coupon|claim your reward|processing fee|"
    r"gift card payment|verify payment details|guaranteed prize|account suspended|"
    r"transaction receipt|completed order receipt|order confirmation)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "seasonal savings are here",
    "save on selected products this week",
    "special offer across our collection",
    "enjoy 20 percent off your next order",
    "limited-time savings for members",
    "weekend sale starts today",
    "explore our current store offers",
    "bundle savings now available",
    "member pricing on popular products",
    "a special shopping offer for you",
    "save more during our seasonal sale",
    "selected items now at lower prices",
    "complimentary shipping this week",
    "current deals from our store",
    "shop the latest savings event",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "general_sales_promotion_detected", "retail_sales_email_detected",
        "store_promotion_detected", "seasonal_sales_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "sales_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner sales-promotion evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a general sales promotion"
    if _SALES_RE.search(text) and _RETAIL_CONTEXT_RE.search(text):
        return "message advertises ordinary store savings, pricing, shipping, or a seasonal sale"
    return ""


def evaluate_general_sales_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type6-general-sales-promotion",
        points=100,
        reason=f"General sales promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="general-sales-promotion-promotional",
    )]
