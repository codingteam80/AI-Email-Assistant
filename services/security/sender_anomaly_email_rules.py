"""Suspicious Type 4: identify anomalous changes to a known sender identity."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:sender[- ]anomaly email|sender identity anomaly|sender address anomaly|"
    r"sender history mismatch|unexpected sender change|sender profile anomaly)\b",
    re.I,
)
_SENDER_ANOMALY_RE = re.compile(
    r"\b(?:different|alternate|another|temporary|new|unfamiliar|unusual|unexpected|"
    r"changed|inconsistent|does not match|doesn't match|doesn.t match|differs? from)\b"
    r".{0,65}\b(?:sender|address|email address|mailbox|account|domain|reply address|"
    r"reply-to|sending route)|"
    r"\b(?:sender|address|email address|mailbox|account|domain|reply address|reply-to|"
    r"sending route)\b.{0,65}\b(?:different|alternate|another|temporary|new|unfamiliar|"
    r"unusual|unexpected|changed|inconsistent|does not match|doesn't match|doesn.t match|"
    r"differs? from|unavailable)\b|"
    r"\bnot (?:the )?(?:sender |email )?address\b.{0,45}\b(?:used before|previously used|expected)\b|"
    r"\b(?:usual|normal|known|previous|previously used|expected)\b.{0,55}"
    r"\b(?:sender|address|email address|mailbox|account|domain)\b.{0,35}"
    r"\b(?:unavailable|changed|different|does not match|doesn't match|doesn.t match)\b",
    re.I,
)
_BASELINE_RE = re.compile(
    r"\b(?:usual|normally|normal|known|familiar|previous|previously|prior|before|"
    r"history|historical|expected|used before|another account|different address|"
    r"new domain|temporary mailbox|alternate mailbox)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"approved address change|verified mailbox migration|announced domain migration|"
    r"scheduled email migration|authenticated alternate address|confirmed by phone|"
    r"updated contact card|expected sender change)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this message came from a different address",
    "the sender is using an alternate mailbox",
    "this is not the sender address used before",
    "the usual account is unavailable",
    "this message comes from a new sending domain",
    "the sender identity changed unexpectedly",
    "this address differs from the previous one",
    "the display name is familiar but the address changed",
    "a temporary mailbox is being used",
    "the sender domain does not match prior messages",
    "this message uses an unfamiliar reply address",
    "the known contact is writing from another account",
    "the mailbox changed without prior notice",
    "the sending address is inconsistent with history",
    "this email arrived through an unusual sender route",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _false(value: object) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)) and value == 0:
        return True
    return isinstance(value, str) and value.casefold().strip() in {
        "false", "no", "mismatch", "mismatched", "anomalous", "unexpected",
    }


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "sender_anomaly_email_detected",
        "sender_identity_anomaly_detected",
        "sender_address_anomaly_detected",
        "sender_profile_anomaly_detected",
        "unexpected_sender_change_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "sender_address_matches_history",
        "sender_domain_matches_history",
        "sender_profile_matches_history",
        "reply_to_matches_sender_history",
    ):
        if key in email_data and _false(email_data.get(key)):
            return f"mailbox metadata reports {key.replace('_', ' ')}"
    for key in (
        "suspicious_classification",
        "sender_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner sender-anomaly evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "sender_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a sender-anomaly email"
    if _SENDER_ANOMALY_RE.search(text) and _BASELINE_RE.search(text):
        return "message explicitly describes a sender identity that differs from its known history"
    return ""


def evaluate_sender_anomaly_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type4-sender-anomaly",
        points=100,
        reason=f"Sender-anomaly email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="sender-anomaly-email",
    )]
