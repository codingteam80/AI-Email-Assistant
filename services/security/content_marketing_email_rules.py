"""Promotional Type 2: identify legitimate content-marketing email."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:content[- ]marketing email|educational marketing content|"
    r"thought[- ]leadership email|resource marketing email)\b",
    re.I,
)
_CONTENT_ASSET_RE = re.compile(
    r"\b(?:guide|article|blog post|white ?paper|webinar|case study|report|ebook|"
    r"checklist|playbook|research brief|expert tips|how[- ]to|resource hub|industry insights)\b",
    re.I,
)
_MARKETING_CONTEXT_RE = re.compile(
    r"\b(?:learn|discover|explore|read|watch|download|view|access|join|register|"
    r"new|latest|featured|on[- ]demand|insights|best practices|strategies|trends)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:requested document|internal report|project checklist|incident report|"
    r"employee training assignment|contract playbook|support article requested by you|"
    r"transaction receipt|security alert|password reset)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "new guide for your team",
    "read our latest industry article",
    "webinar insights now available",
    "customer success case study",
    "download the new research brief",
    "expert tips for better workflows",
    "on-demand webinar resources",
    "latest trends and strategies",
    "new whitepaper available",
    "featured article and insights",
    "practical checklist for teams",
    "explore our resource hub",
    "industry report highlights",
    "new playbook for growing teams",
    "content insights from our experts",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "content_marketing_email_detected", "educational_marketing_content_detected",
        "thought_leadership_email_detected", "marketing_resource_email_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "marketing_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner content-marketing evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies content marketing"
    if _CONTENT_ASSET_RE.search(text) and _MARKETING_CONTEXT_RE.search(text):
        return "email promotes an educational resource, article, webinar, or thought-leadership asset"
    return ""


def evaluate_content_marketing_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type2-content-marketing",
        points=100,
        reason=f"Content-marketing email detected ({reason})",
        categories=("Promotional",),
        strong_flag="content-marketing-promotional",
    )]
