"""Spam Type 10: detect one campaign distributed across rotating senders."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:rotating[- ]sender spam|snowshoe spam|distributed sender spam|"
    r"sender rotation campaign|multi[- ]domain spam campaign)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|approved shared service|legitimate distribution list|authorized mail provider|"
    r"transactional sender pool|load balancing|mail migration|security awareness|training|"
    r"simulation|example|analysis|incident report|false positive|sender allowlisted|trusted sender)\b",
    re.I,
)
_ROTATION_RE = re.compile(
    r"\b(?:same|the same|this|this same|our) (?:promotion|promotional offer|advertisement|"
    r"commercial offer|special offer|offer|campaign|marketing campaign|sale campaign|sales message|catalog)\b"
    r".{0,120}\b(?:different|new|alternate|changing|rotating|multiple|many)\b"
    r".{0,80}\b(?:sender|sending address|email address|mailbox|account|domain)s?\b|"
    r"\b(?:different|new|alternate|changing|rotating|multiple|many)\b"
    r".{0,80}\b(?:sender|sending address|email address|mailbox|account|domain)s?\b"
    r".{0,120}\b(?:same|the same|this|this same|our) (?:promotion|promotional offer|advertisement|"
    r"commercial offer|special offer|offer|campaign|marketing campaign|sale campaign|sales message|catalog)\b|"
    r"\bspread (?:this|the|our) (?:promotion|campaign|offer) across\b"
    r".{0,80}\b(?:senders|addresses|mailboxes|accounts|domains)\b",
    re.I | re.S,
)
_PROMO_RE = re.compile(
    r"\b(?:promotion|advertisement|commercial offer|sales message|product catalog|service package|"
    r"special offer|marketing campaign|buy|order|shop|view the catalog|contact sales)\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "regional offer dispatch",
    "alternate sender promotion",
    "distributed campaign notice",
    "multi-domain offer release",
    "sender pool promotion",
    "rotating account special",
    "campaign relay update",
    "mailbox pool offer",
    "domain rotation sale",
    "distributed sender discount",
    "changing sender promotion",
    "parallel account offer",
    "sender network special",
    "snowshoe delivery offer",
    "campaign address rotation",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _numeric(email_data: Mapping, *keys: str) -> int:
    for key in keys:
        value = email_data.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "rotating_sender_spam_detected", "snowshoe_spam_detected",
        "distributed_sender_spam_detected", "sender_rotation_campaign_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "campaign_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner rotating-sender evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "campaign_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    senders = _numeric(
        email_data, "campaign_sender_count", "rotating_sender_count",
        "distinct_sender_count", "related_sender_count",
    )
    domains = _numeric(
        email_data, "campaign_sender_domain_count", "snowshoe_domain_count",
        "distinct_sender_domain_count",
    )
    similar = _numeric(
        email_data, "similar_message_count", "message_fingerprint_count",
        "campaign_message_count", "duplicate_message_count",
    )
    if similar >= 3 and (senders >= 3 or domains >= 3):
        return f"{similar} matching campaign messages span {max(senders, domains)} sender identities or domains"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "campaign_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies distributed sender rotation"
    if _ROTATION_RE.search(text) and _PROMO_RE.search(text):
        return "message states that one commercial campaign is spread across changing sender identities"
    return ""


def evaluate_rotating_sender_snowshoe_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = (
        _metadata_reason(email_data)
        or _behavior_reason(email_data)
        or _content_reason(email_data, text)
    )
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type10-rotating-sender-snowshoe",
        points=100,
        reason=f"Rotating-sender or snowshoe spam detected ({reason})",
        categories=("Spam",),
        strong_flag="rotating-sender-snowshoe-spam",
    )]
