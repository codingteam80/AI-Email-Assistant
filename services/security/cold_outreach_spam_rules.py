"""Spam Type 4: detect unsolicited first-contact sales outreach."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:cold outreach spam|unsolicited sales outreach|cold sales email|unrequested prospecting email)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|solicited|requested (?:contact|information|demo|proposal)|"
    r"(?:information|demo|proposal) you requested|referred by|"
    r"existing vendor|current vendor|active project|active conversation|scheduled meeting|"
    r"current customer|existing customer|sender allowlisted|trusted sender|false positive|"
    r"security awareness|training|simulation|example|analysis)\b",
    re.I,
)
_CONTENT_CLEAN_RE = re.compile(
    r"\b(?:not spam|solicited|requested (?:contact|information|demo|proposal)|"
    r"(?:information|demo|proposal) you requested|referred by|"
    r"existing vendor|current vendor|active project|active conversation|scheduled meeting|"
    r"current customer|existing customer|sender allowlisted|trusted sender|false positive|"
    r"security awareness|training|simulation)\b",
    re.I,
)
_FIRST_CONTACT_RE = re.compile(
    r"\b(?:i(?:'m| am) reaching out (?:because|after|as)|reaching out after (?:finding|seeing)|"
    r"came across your (?:company|business|profile|website|team)|noticed your (?:company|business|team|work)|"
    r"found your (?:company|business|profile|website)|this is my first (?:note|message|introduction)|"
    r"wanted to introduce (?:myself|our company|our team)|contacting you for the first time)\b",
    re.I,
)
_PITCH_RE = re.compile(
    r"\b(?:we help (?:companies|businesses|teams|organizations)|our (?:team|company|agency) (?:provides|offers|helps)|"
    r"our (?:service|platform|solution) (?:helps|can|is designed)|we provide (?:a |an )?(?:service|platform|solution)|"
    r"our consulting (?:service|team)|we specialize in|we support (?:companies|businesses|teams))\b",
    re.I,
)
_CTA_RE = re.compile(
    r"\b(?:open to (?:a )?(?:brief|quick|short) (?:call|conversation|chat)|"
    r"schedule (?:a )?(?:brief|quick|short|15-minute) (?:call|conversation|meeting)|"
    r"book (?:a )?(?:demo|call|meeting)|can i send (?:more |additional )?(?:details|information)|"
    r"reply if (?:this is|you are) interested|available (?:for a call|to talk|this week)|"
    r"would you have \d{1,2} minutes|would you be willing to talk)\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "an introduction for your business",
    "introducing a planning service",
    "a possible workflow conversation",
    "a conversation about team organization",
    "introducing our coordination platform",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "cold_outreach_spam_detected", "unsolicited_sales_outreach_detected",
        "cold_sales_email_detected", "unrequested_prospecting_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner cold-outreach evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CONTENT_CLEAN_RE.search(text):
        return ""
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS:
        return "reported cold-outreach subject recognized before full body synchronization"
    if _FIRST_CONTACT_RE.search(text) and _PITCH_RE.search(text) and _CTA_RE.search(text):
        return "first-contact prospecting combines a sales pitch with a meeting or reply request"
    return ""


def evaluate_cold_outreach_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type4-cold-outreach",
        points=100,
        reason=f"Cold outreach spam detected ({reason})",
        categories=("Spam",),
        strong_flag="cold-outreach-spam",
    )]
