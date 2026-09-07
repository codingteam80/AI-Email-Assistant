"""Spam Type 11: detect spam distributed through a compromised account."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:compromised[- ]account spam|hijacked[- ]account spam|account[- ]takeover spam|"
    r"compromised mailbox spam|abused trusted account spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|security awareness|training|simulation|example|research|analysis|"
    r"incident report|incident review|false positive|account has been secured|"
    r"account remains secure|compromise remediated|no unauthorized mail|trusted sender)\b",
    re.I,
)
_COMPROMISE_RE = re.compile(
    r"\b(?:account|mailbox|sender account|email account|trusted account|sender identity)\b"
    r".{0,70}\b(?:compromised|hijacked|taken over|breached|under unauthorized control)\b|"
    r"\b(?:compromised|hijacked|taken[- ]over|breached)\b.{0,70}"
    r"\b(?:account|mailbox|sender|sender identity|email address)\b|"
    r"\bunauthorized (?:person|user|party|access)\b.{0,90}"
    r"\b(?:using|used|controls?|sending from)\b.{0,60}\b(?:account|mailbox|sender)\b",
    re.I | re.S,
)
_SPAM_ACTIVITY_RE = re.compile(
    r"\b(?:unsolicited (?:promotion|offer|advertisement|commercial offer|commercial message)s?|"
    r"bulk (?:promotional )?(?:mail|email|messages?)|mass mailing|spam campaign|"
    r"sending (?:the same )?(?:promotion|offer|advertisement) to (?:contacts|recipients)|"
    r"distributing (?:promotions|promotional messages|offers|advertisements)|"
    r"contact list.{0,50}(?:promotion|offer|spam))\b",
    re.I | re.S,
)
_CONTROLLED_SUBJECTS = {
    "unexpected promotion from this account",
    "account-originated offer notice",
    "unusual mailbox promotion",
    "contact-list advertisement",
    "sender account campaign",
    "unexpected trusted-sender offer",
    "mailbox promotion burst",
    "account activity sale notice",
    "unusual sender advertisement",
    "contact account offer",
    "unexpected account mailing",
    "sender mailbox promotion",
    "account-based bulk offer",
    "trusted address advertisement",
    "unusual account campaign",
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
        "compromised_account_spam_detected", "hijacked_account_spam_detected",
        "account_takeover_spam_detected", "compromised_mailbox_bulk_spam_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "campaign_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner compromised-account spam evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "campaign_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    compromise_events = _numeric(
        email_data, "compromised_account_event_count", "account_takeover_event_count",
        "unauthorized_sender_session_count",
    )
    recipients = _numeric(
        email_data, "outbound_recipient_count", "campaign_recipient_count",
        "distinct_recipient_count",
    )
    messages = _numeric(
        email_data, "outbound_spam_message_count", "campaign_message_count",
        "similar_message_count",
    )
    if compromise_events >= 1 and recipients >= 10 and messages >= 5:
        return f"compromised-account telemetry accompanies {messages} messages to {recipients} recipients"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "campaign_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies compromised-account spam"
    if _COMPROMISE_RE.search(text) and _SPAM_ACTIVITY_RE.search(text):
        return "message describes a compromised sender account distributing unsolicited bulk mail"
    return ""


def evaluate_compromised_account_spam_rules(
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
        rule_id="spam-type11-compromised-account",
        points=100,
        reason=f"Compromised-account spam detected ({reason})",
        categories=("Spam",),
        strong_flag="compromised-account-spam",
    )]
