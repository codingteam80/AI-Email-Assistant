"""Promotional Type 3: identify legitimate brand-awareness email."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:brand[- ]awareness email|brand story campaign|corporate identity campaign|"
    r"mission and values campaign)\b",
    re.I,
)
_BRAND_IDENTITY_RE = re.compile(
    r"\b(?:our brand|our story|our mission|our values|who we are|what we stand for|"
    r"our journey|company culture|behind our name|behind the brand|our commitment|"
    r"our community|community impact|positive impact|sustainability|anniversary)\b",
    re.I,
)
_AWARENESS_CONTEXT_RE = re.compile(
    r"\b(?:discover|meet|learn|explore|celebrat(?:e|ing)|proud|together|inspire|"
    r"building|creating|closer look|support|future|people|ideas)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:invoice due|wire transfer|payment details|internal incident|delivery failure)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "discover the story behind our brand",
    "our mission and values",
    "building a better future together",
    "meet the people behind our name",
    "celebrating our community",
    "a closer look at who we are",
    "our journey so far",
    "what our brand stands for",
    "creating positive impact together",
    "inside our company culture",
    "celebrating another year together",
    "our commitment to sustainability",
    "the ideas that inspire us",
    "proud to support our community",
    "get to know our brand",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "brand_awareness_email_detected", "brand_story_campaign_detected",
        "corporate_identity_campaign_detected", "mission_values_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "brand_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner brand-awareness evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies brand awareness"
    if _BRAND_IDENTITY_RE.search(text) and _AWARENESS_CONTEXT_RE.search(text):
        return "message promotes brand identity, mission, values, culture, or community impact"
    return ""


def evaluate_brand_awareness_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type3-brand-awareness",
        points=100,
        reason=f"Brand-awareness email detected ({reason})",
        categories=("Promotional",),
        strong_flag="brand-awareness-promotional",
    )]
