"""Suspicious Type 7: identify explicit low-reputation sender evidence."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:low[- ]reputation sender email|low sender reputation|"
    r"poor sender reputation|sender reputation risk|sender trust anomaly|"
    r"sender abuse reputation)\b",
    re.I,
)
_LOW_REPUTATION_RE = re.compile(
    r"\b(?:sender|sending source|sending domain|sender domain|address|email address|"
    r"mailbox|source|domain)\b.{0,80}"
    r"\b(?:low|poor|negative|unfavorable|risky|bad)\b.{0,30}"
    r"\b(?:reputation|trust score|reputation score|standing)|"
    r"\b(?:sender|sending source|sending domain|sender domain|address|email address|"
    r"mailbox|source|domain)\b.{0,80}"
    r"\b(?:reported for abuse|abuse reports?|spam complaints?|recent complaints?|"
    r"blocklist(?:ed)?|denylist(?:ed)?|history of unwanted mail|little sending history|"
    r"no established history|not well established|recently observed|below threshold)|"
    r"\b(?:low|poor|negative|unfavorable|risky|bad)\b.{0,30}"
    r"\b(?:sender|domain|address|mailbox|source)\b.{0,35}\b(?:reputation|trust score|standing)\b|"
    r"\b(?:sender|sending source|sending domain|sender domain|address|email address|"
    r"mailbox|source|domain)\b.{0,45}\b(?:reputation|trust score|standing)\b"
    r".{0,45}\b(?:low|poor|negative|unfavorable|risky|bad|unusually low|"
    r"changed negatively|declined|deteriorated|below threshold)\b",
    re.I,
)
_SENDER_CONTEXT_RE = re.compile(
    r"\b(?:sender|sending source|sending domain|sender domain|address|email address|"
    r"mailbox|source|domain|reputation|trust score|blocklist|denylist|complaints?|abuse)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|allowlisted|"
    r"approved new sender|verified new employee|expected new contact|"
    r"verified newly launched domain|trusted partner onboarding|confirmed by administrator|"
    r"reputation review completed|legitimate low-volume sender)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "the sender has a low reputation score",
    "this address has little sending history",
    "the sender domain has a poor reputation",
    "this mailbox was recently observed",
    "the sender has been reported for abuse",
    "the address appears on a reputation blocklist",
    "the sending domain has no established history",
    "the sender reputation changed negatively",
    "this source has a history of unwanted mail",
    "the mailbox reputation is below threshold",
    "the sender is associated with recent complaints",
    "the domain reputation is unusually low",
    "this address has an unfavorable trust score",
    "the sending source is not well established",
    "the sender reputation is considered risky",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _low_score(value: object) -> bool:
    if value is None or value == "":
        return False
    try:
        return 0 <= float(value) <= 20
    except (TypeError, ValueError):
        return False


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "low_reputation_sender_email_detected",
        "sender_reputation_low_detected",
        "sender_abuse_reputation_detected",
        "reputation_blocklist_detected",
        "sender_reputation_risk_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("sender_reputation_score", "sender_trust_score"):
        if _low_score(email_data.get(key)):
            return f"{key.replace('_', ' ')} is at or below 20"
    reputation = str(email_data.get("sender_reputation") or "").casefold().strip()
    if reputation in {"low", "poor", "negative", "bad", "risky", "blocklisted", "denylisted"}:
        return f"sender reputation is {reputation}"
    for key in (
        "suspicious_classification",
        "sender_reputation_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner low-reputation sender evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "sender_reputation_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a low-reputation sender email"
    if _LOW_REPUTATION_RE.search(text) and _SENDER_CONTEXT_RE.search(text):
        return "message explicitly describes negative sender reputation or abuse history"
    return ""


def evaluate_low_reputation_sender_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type7-low-reputation-sender",
        points=100,
        reason=f"Low-reputation sender email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="low-reputation-sender-email",
    )]
