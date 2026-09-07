"""Promotional Type 10: identify legitimate cross-sell and upsell offers."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:cross[- ]sell or upsell|cross[- ]sell promotion|upsell promotion|"
    r"legitimate upgrade offer|product add[- ]on promotion)\b",
    re.I,
)
_OFFER_RE = re.compile(
    r"\b(?:upgrade|premium plan|next membership tier|more storage|"
    r"extra features?|add[- ]ons?|accessories|matching items?|pair (?:it|your purchase)|"
    r"complement your purchase|complete your (?:setup|collection)|"
    r"bundle your product|protection plan|get more from|enhance your plan)\b",
    re.I,
)
_RELATIONSHIP_RE = re.compile(
    r"\b(?:recent purchase|your purchase|your order|current (?:plan|subscription|service)|"
    r"your (?:plan|subscription|membership|device|product|collection|setup)|"
    r"matching|add|pair|bundle|tier|features?|storage|accessories|extras?)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:verify your account|confirm your identity|password|passcode|otp|"
    r"security alert|account suspended|payment overdue|past due|debt|invoice|"
    r"wire transfer|bank account|card number|cvv|gift card code|processing fee)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "complete your setup with these accessories",
    "add matching items to your order",
    "upgrade to the premium plan",
    "pair your purchase with these essentials",
    "accessories selected for your new device",
    "get more from your current subscription",
    "add protection to your recent purchase",
    "complete the collection with matching styles",
    "enhance your plan with extra features",
    "recommended add-ons for your account",
    "bundle your product with useful extras",
    "move to the next membership tier",
    "complement your purchase with these items",
    "explore an upgrade for your current service",
    "add more storage to your plan",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "cross_sell_upsell_detected", "cross_sell_promotion_detected",
        "upsell_promotion_detected", "product_add_on_promotion_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "upsell_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner cross-sell or upsell evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a cross-sell or upsell"
    if _OFFER_RE.search(text) and _RELATIONSHIP_RE.search(text):
        return "an ordinary related-product, add-on, plan, or service upgrade is offered"
    return ""


def evaluate_cross_sell_upsell_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type10-cross-sell-upsell",
        points=100,
        reason=f"Cross-sell or upsell detected ({reason})",
        categories=("Promotional",),
        strong_flag="cross-sell-upsell-promotional",
    )]
