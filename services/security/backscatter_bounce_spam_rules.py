"""Spam Type 14: detect unsolicited delivery failures caused by forged sender traffic."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:backscatter spam|bounce spam|unsolicited bounce|forged[- ]sender bounce|"
    r"misdirected non[- ]delivery report)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:legitimate delivery failure|expected bounce|message you sent|requested delivery report|"
    r"known outbound message|security awareness|training|simulation|example|analysis|"
    r"incident report|false positive|delivery test|mail administrator report)\b",
    re.I,
)
_DSN_RE = re.compile(
    r"\b(?:delivery status notification|non[- ]delivery report|undeliverable|undelivered|"
    r"delivery failure|delivery failed|returned mail|failure notice|bounce message)\b",
    re.I,
)
_UNSOLICITED_RE = re.compile(
    r"\b(?:message (?:that )?you did not send|mail (?:that )?you never sent|"
    r"unknown (?:outbound )?message|no matching outbound message|not sent from your mailbox|"
    r"forged (?:sender|from|return) address|spoofed (?:sender|from|return) address|"
    r"unsolicited (?:bounce|delivery failure|non[- ]delivery report)|"
    r"bounce for (?:an )?unrecognized message|backscatter)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "delivery failure for a message you did not send",
    "undeliverable unknown outbound message",
    "returned mail from a forged sender",
    "unsolicited delivery status notification",
    "bounce for an unrecognized message",
    "non-delivery report for unknown mail",
    "delivery failed for mail you never sent",
    "unexpected returned mail notice",
    "forged-sender bounce notification",
    "unknown message delivery failure",
    "backscatter delivery notice",
    "unexpected non-delivery report",
    "returned message not sent by you",
    "unsolicited bounce message",
    "delivery failure from spoofed mail",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _false(value: object) -> bool:
    return value is False or value == 0 or (isinstance(value, str) and value.casefold().strip() in {"false", "no", "0"})


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
        "backscatter_spam_detected", "bounce_spam_detected",
        "unsolicited_bounce_detected", "forged_sender_bounce_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "bounce_analysis", "dsn_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner backscatter evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "bounce_analysis", "dsn_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    not_sent = _false(email_data.get("original_message_sent_by_user")) or _true(
        email_data.get("no_matching_outbound_message")
    )
    bounce_count = _numeric(email_data, "unsolicited_bounce_count", "backscatter_message_count", "bounce_message_count")
    if not_sent and (bounce_count >= 1 or _DSN_RE.search(text)):
        return "delivery report has no matching user-originated outbound message"
    if _true(email_data.get("forged_envelope_sender_detected")) and _DSN_RE.search(text):
        return "delivery report was generated from a forged envelope sender"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "bounce_analysis", "dsn_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies unsolicited backscatter"
    if _DSN_RE.search(text) and _UNSOLICITED_RE.search(text):
        return "unsolicited delivery failure refers to mail the recipient did not originate"
    return ""


def evaluate_backscatter_bounce_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, text) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type14-backscatter-bounce",
        points=100,
        reason=f"Backscatter or bounce spam detected ({reason})",
        categories=("Spam",),
        strong_flag="backscatter-bounce-spam",
    )]
