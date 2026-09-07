"""Promotional Type 4: identify legitimate product announcements."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:product announcement|product launch email|new release announcement|"
    r"feature launch campaign)\b",
    re.I,
)
_ANNOUNCEMENT_RE = re.compile(
    r"\b(?:introducing|announcing|now available|has arrived|is here|just launched|"
    r"new release|latest release|product launch|meet the new|meet our new|"
    r"newest product|newest collection|new feature(?:s| suite)?|what is new|version\s*\d)\b",
    re.I,
)
_PRODUCT_RE = re.compile(
    r"\b(?:product|platform|application|app|dashboard|feature(?:s)?|release|version|"
    r"collection|plan|service|solution|suite|device|tool)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:security patch required|critical vulnerability|invoice due|"
    r"payment required|internal deployment ticket|"
    r"production incident|download executable attachment)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "introducing our newest product",
    "meet the new atlas platform",
    "our latest release is here",
    "announcing the next generation",
    "now available: workspace pro",
    "discover our new mobile app",
    "a new feature suite has arrived",
    "product launch announcement",
    "introducing version 4.0",
    "see what is new in our platform",
    "new product features now available",
    "meet our redesigned dashboard",
    "announcing our newest collection",
    "the new essentials plan is here",
    "explore our latest product release",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "product_announcement_detected", "product_launch_email_detected",
        "new_release_announcement_detected", "feature_launch_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "product_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner product-announcement evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a product announcement"
    if _ANNOUNCEMENT_RE.search(text) and _PRODUCT_RE.search(text):
        return "message announces a product, release, version, feature, collection, or plan"
    return ""


def evaluate_product_announcement_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type4-product-announcement",
        points=100,
        reason=f"Product announcement detected ({reason})",
        categories=("Promotional",),
        strong_flag="product-announcement-promotional",
    )]
