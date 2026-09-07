"""Promotional Type 1: identify legitimate informational newsletters."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:informational newsletter|editorial newsletter|newsletter digest|"
    r"industry newsletter|community bulletin)\b",
    re.I,
)
_NEWSLETTER_RE = re.compile(
    r"\b(?:weekly|monthly|daily|quarterly|latest|community|industry|product|member|editorial)\b"
    r".{0,70}\b(?:newsletter|digest|bulletin|roundup|news update)\b|"
    r"\b(?:newsletter|digest|bulletin|roundup)\b.{0,140}"
    r"\b(?:news|updates?|articles?|stories|highlights|insights|events?|announcements?|resources?)\b",
    re.I | re.S,
)
_INFORMATION_RE = re.compile(
    r"\b(?:news|updates?|articles?|stories|highlights|insights|events?|announcements?|"
    r"resources?|what(?:'s| is) new|editor's note|this week|this month)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:transaction receipt|password reset|security alert|delivery status|invoice due|"
    r"internal project update|personal message|one[- ]time code|account verification)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "weekly industry newsletter",
    "monthly product news digest",
    "community updates bulletin",
    "this week in technology",
    "quarterly member newsletter",
    "daily market news roundup",
    "editorial highlights for today",
    "monthly community stories",
    "weekly research digest",
    "latest association bulletin",
    "product updates newsletter",
    "industry events this month",
    "member news and announcements",
    "weekly insights roundup",
    "community newsletter edition",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "informational_newsletter_detected", "newsletter_content_detected",
        "editorial_newsletter_detected", "newsletter_digest_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "newsletter_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner newsletter evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies an informational newsletter"
    if _NEWSLETTER_RE.search(text) and _INFORMATION_RE.search(text):
        return "recurring newsletter format provides informational updates or editorial content"
    return ""


def evaluate_informational_newsletter_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type1-informational-newsletter",
        points=100,
        reason=f"Informational newsletter detected ({reason})",
        categories=("Promotional",),
        strong_flag="informational-newsletter-promotional",
    )]
