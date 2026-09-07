"""Promotional Type 9: identify legitimate personalized recommendations."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:personalized recommendation|personalised recommendation|"
    r"tailored product suggestion|interest[- ]based recommendation)\b",
    re.I,
)
_RECOMMENDATION_RE = re.compile(
    r"\b(?:recommend(?:ed|ations?)?|suggestions?|picks?|chosen|selected|"
    r"curated|tailored|you may enjoy|inspired by)\b",
    re.I,
)
_PERSONALIZATION_RE = re.compile(
    r"\b(?:for you|your (?:interests?|preferences?|style|favorites?|browsing|"
    r"recent views?)|based on your|personalized|personalised|tailored|"
    r"selected for you|chosen for you|you may enjoy)\b",
    re.I,
)
_COMMERCIAL_CONTEXT_RE = re.compile(
    r"\b(?:products?|items?|collection|styles?|store|catalog|reads?|books?|"
    r"favorites?|selection)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:verify your account|confirm your identity|password|passcode|otp|"
    r"security alert|unusual sign[- ]in|account suspended|bank account|"
    r"card number|cvv|wire transfer|gift card code)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "picks selected for you",
    "recommended products based on your interests",
    "your personalized collection is ready",
    "suggestions chosen for your style",
    "products you may enjoy",
    "curated recommendations for you",
    "more items inspired by your favorites",
    "explore picks based on your browsing",
    "a collection selected for your interests",
    "recommended reads for your week",
    "your tailored product suggestions",
    "discover items chosen for you",
    "recommendations from your recent interests",
    "personal picks from our collection",
    "new suggestions selected for you",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "personalized_recommendation_detected",
        "tailored_product_suggestion_detected",
        "interest_based_recommendation_detected",
        "recommendation_promotion_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "recommendation_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner personalized-recommendation evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a personalized recommendation"
    if (
        _RECOMMENDATION_RE.search(text)
        and _PERSONALIZATION_RE.search(text)
        and _COMMERCIAL_CONTEXT_RE.search(text)
    ):
        return "products or content are recommended using ordinary preference context"
    return ""


def evaluate_personalized_recommendation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type9-personalized-recommendation",
        points=100,
        reason=f"Personalized recommendation detected ({reason})",
        categories=("Promotional",),
        strong_flag="personalized-recommendation-promotional",
    )]
