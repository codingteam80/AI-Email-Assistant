"""Promotional Type 15: identify disclosed sponsored or affiliate promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:sponsored or affiliate promotion|sponsored promotion|"
    r"affiliate promotion|partner marketing promotion)\b",
    re.I,
)
_DISCLOSURE_RE = re.compile(
    r"\b(?:sponsored|sponsor|affiliate|affiliate link|paid partnership|"
    r"partner promotion|from our partner|partner spotlight|partner products?)\b",
    re.I,
)
_PROMOTIONAL_CONTEXT_RE = re.compile(
    r"\b(?:offer|promotion|products?|collection|recommendation|marketplace|"
    r"featured|selection|store|brand|product highlights?|picks?)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:change (?:the )?(?:bank|payment) details|new bank account|"
    r"wire transfer|send payment|invoice|payment overdue|confirm your identity|"
    r"verify your account|password|passcode|otp|card number|cvv|gift card code|"
    r"processing fee|investment return|guaranteed profit)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "sponsored picks from our partner",
    "a featured offer from our affiliate",
    "partner promotion: selected products",
    "sponsored collection from a trusted brand",
    "discover this affiliate offer",
    "featured partner products this week",
    "a sponsored recommendation for you",
    "partner spotlight and special offer",
    "explore products from our sponsor",
    "affiliate selection from our marketplace",
    "sponsored content: product highlights",
    "this week's partner promotion",
    "featured brand offer from our partner",
    "recommended products from an affiliate",
    "a sponsored store collection",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "sponsored_affiliate_promotion_detected", "sponsored_promotion_detected",
        "affiliate_promotion_detected", "partner_marketing_promotion_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "affiliate_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner sponsored-or-affiliate evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a sponsored or affiliate promotion"
    if _DISCLOSURE_RE.search(text) and _PROMOTIONAL_CONTEXT_RE.search(text):
        return "a disclosed sponsor, affiliate, or marketing partner promotes ordinary products"
    return ""


def evaluate_sponsored_affiliate_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type15-sponsored-affiliate",
        points=100,
        reason=f"Sponsored or affiliate promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="sponsored-affiliate-promotional",
    )]
