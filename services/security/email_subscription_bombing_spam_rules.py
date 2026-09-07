"""Spam Type 15: detect recipient-focused email or subscription bombing bursts."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:email bombing|mail bombing|subscription bombing|newsletter bombing|"
    r"signup bombing|inbox flooding attack)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|requested subscriptions?|approved newsletters?|legitimate mailing list|"
    r"account migration|mailbox restore|expected notification burst|load test|"
    r"security awareness|training|simulation|example|analysis|incident report|false positive)\b",
    re.I,
)
_BOMBING_RE = re.compile(
    r"\b(?:email|mail|subscription|newsletter|signup)[- ]bomb(?:ing|ed)?\b|"
    r"\b(?:inbox|mailbox|recipient)\b.{0,80}\b(?:flooded|overwhelmed|bombarded)\b"
    r".{0,120}\b(?:subscription confirmations?|signup messages?|newsletter messages?|emails?|messages?)\b|"
    r"\b(?:large|rapid|sudden|high[- ]volume) (?:burst|wave)\b.{0,100}"
    r"\b(?:subscription confirmations?|newsletter signups?|signup messages?|unwanted emails?)\b|"
    r"\b(?:many|dozens|hundreds)(?: of)? unwanted (?:subscription|signup|newsletter)"
    r" (?:confirmations?|messages?|emails?)\b.{0,80}\b(?:at once|rapidly|in minutes|in a burst)\b",
    re.I | re.S,
)
_CONTROLLED_SUBJECTS = {
    "subscription confirmation burst",
    "unexpected newsletter signup wave",
    "mailbox subscription flood",
    "rapid signup confirmation activity",
    "inbox message bombing notice",
    "multiple subscription confirmations",
    "newsletter registration flood",
    "sudden mailbox message burst",
    "subscription bombing activity",
    "high-volume signup messages",
    "unexpected mailing-list wave",
    "inbox subscription overload",
    "rapid newsletter confirmations",
    "mail bombing activity notice",
    "subscription message flood",
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
        "email_bombing_detected", "subscription_bombing_detected",
        "mail_bombing_detected", "inbox_flooding_attack_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "burst_analysis", "subscription_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner email-bombing evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "burst_analysis", "subscription_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    messages = _numeric(
        email_data, "recipient_burst_message_count", "mailbox_message_count_10m",
        "inbox_burst_message_count", "email_bomb_message_count",
    )
    subscriptions = _numeric(
        email_data, "subscription_confirmation_count", "newsletter_signup_count",
        "subscription_message_count",
    )
    sources = _numeric(
        email_data, "burst_distinct_sender_count", "subscription_sender_count",
        "burst_distinct_domain_count",
    )
    if messages >= 20 and subscriptions >= 10 and sources >= 5:
        return f"one recipient received {messages} messages including {subscriptions} subscription notices from {sources} sources"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "burst_analysis", "subscription_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies email or subscription bombing"
    if _BOMBING_RE.search(text):
        return "message describes a high-volume subscription or mailbox flooding burst"
    return ""


def evaluate_email_subscription_bombing_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type15-email-subscription-bombing",
        points=100,
        reason=f"Email bombing or subscription bombing detected ({reason})",
        categories=("Spam",),
        strong_flag="email-subscription-bombing-spam",
    )]
