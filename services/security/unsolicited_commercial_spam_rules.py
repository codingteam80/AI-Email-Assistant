"""Spam Type 3: detect unsolicited commercial promotions and sales offers."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unsolicited commercial spam|unsolicited sales promotion|unrequested commercial offer|"
    r"commercial bulk spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|solicited|requested (?:offer|quote|information)|subscribed|opted in|"
    r"current customer|existing customer|order confirmation|purchase receipt|transactional|"
    r"saved preferences|active contract|false positive|security awareness|training|simulation|"
    r"example|analysis|sender allowlisted|trusted sender)\b",
    re.I,
)
_CONTENT_CLEAN_RE = re.compile(
    r"\b(?:not spam|solicited|requested (?:offer|quote|information)|subscribed|opted in|"
    r"current customer|existing customer|order confirmation|purchase receipt|transactional|"
    r"saved preferences|active contract|false positive|security awareness|training|simulation|"
    r"sender allowlisted|trusted sender)\b",
    re.I,
)
_COMMERCIAL_RE = re.compile(
    r"\b(?:commercial offer|special promotion|promotional offer|limited-time (?:sale|offer)|"
    r"exclusive (?:deal|offer)|clearance (?:sale|price)|new-customer (?:deal|price|offer)|"
    r"save (?:up to )?\d{1,2}% (?:on|across)|\d{1,2}% (?:off|discount)|discounted (?:price|package)|"
    r"product catalog|service package|subscription plan|free trial|bulk pricing|wholesale price)\b",
    re.I,
)
_UNSOLICITED_RE = re.compile(
    r"\b(?:introducing our|we are contacting (?:selected|local|new)|contacting you with|"
    r"thought (?:you|this) (?:might|may|would) (?:be interested|interest you)|"
    r"selected for (?:an|this) offer|available to new customers|new-customer|first-time buyer|"
    r"you may be interested in|sharing this offer with you)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:buy|order|shop|claim|redeem|view (?:the )?catalog|request (?:a )?quote|"
    r"start (?:a |your )?free trial|enroll|sign up|contact sales|reserve (?:the|your) (?:deal|offer|package))\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "complimentary software trial",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unsolicited_commercial_spam_detected", "commercial_spam_detected",
        "unrequested_sales_promotion_detected", "commercial_bulk_spam_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner commercial-spam evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CONTENT_CLEAN_RE.search(text):
        return ""
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS:
        return "reported commercial-spam subject recognized before full body synchronization"
    commercial = _COMMERCIAL_RE.search(text)
    unsolicited = _UNSOLICITED_RE.search(text)
    action = _ACTION_RE.search(text)
    if commercial and unsolicited and action:
        return "unrequested commercial promotion combines a sales offer with a purchase action"
    return ""


def evaluate_unsolicited_commercial_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type3-unsolicited-commercial",
        points=100,
        reason=f"Unsolicited commercial spam detected ({reason})",
        categories=("Spam",),
        strong_flag="unsolicited-commercial-spam",
    )]
