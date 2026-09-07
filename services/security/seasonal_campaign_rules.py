"""Promotional Type 8: identify legitimate seasonal campaigns."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:seasonal campaign|holiday marketing campaign|seasonal collection email|"
    r"annual retail campaign)\b",
    re.I,
)
_SEASON_RE = re.compile(
    r"\b(?:spring|summer|autumn|fall|winter|holiday season|holidays?|new year|"
    r"year[- ]end|back[- ]to[- ]school|seasonal)\b",
    re.I,
)
_CAMPAIGN_RE = re.compile(
    r"\b(?:campaign|collection|favorites?|essentials?|styles?|inspiration|"
    r"season|celebrate|gifting|preview|highlights?|picks?|moments?|has arrived|"
    r"now available|is here)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:weather alert|school closure|holiday schedule|office closure|"
    r"seasonal illness|tax year[- ]end report|calendar reminder)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "welcome to our spring collection",
    "summer campaign highlights",
    "our autumn favorites are here",
    "winter collection now available",
    "holiday season at our store",
    "celebrate the new year with us",
    "back-to-school collection",
    "our year-end campaign",
    "spring styles for the new season",
    "summer essentials have arrived",
    "autumn inspiration from our brand",
    "winter moments and seasonal picks",
    "holiday gifting collection",
    "new year collection preview",
    "seasonal favorites for the family",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "seasonal_campaign_detected", "holiday_marketing_campaign_detected",
        "seasonal_collection_email_detected", "annual_retail_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "seasonal_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner seasonal-campaign evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a seasonal campaign"
    if _SEASON_RE.search(text) and _CAMPAIGN_RE.search(text):
        return "message promotes a seasonal, holiday, or annual branded campaign"
    return ""


def evaluate_seasonal_campaign_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type8-seasonal-campaign",
        points=100,
        reason=f"Seasonal campaign detected ({reason})",
        categories=("Promotional",),
        strong_flag="seasonal-campaign-promotional",
    )]
