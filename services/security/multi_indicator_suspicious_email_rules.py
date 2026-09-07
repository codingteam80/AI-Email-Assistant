"""Suspicious Type 15: identify messages with multiple independent indicators."""
from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_COMPONENT_FLAGS = {
    "unusual-content-email", "unexpected-contact-email", "context-mismatch-email",
    "sender-anomaly-email", "authentication-anomaly-email", "header-inconsistency-email",
    "low-reputation-sender-email", "suspicious-link-email", "suspicious-attachment-email",
    "unscannable-content-email", "unusual-request-email", "pressure-secrecy-email",
    "known-sender-behavioral-anomaly", "reconnaissance-email", "campaign-associated-email",
    "pending-analysis-threat", "ai-prompt-injection-email",
}
_ANALYSIS_RE = re.compile(
    r"\b(?:multi[- ]indicator suspicious email|multiple suspicious indicators|"
    r"multiple independent warning signs|combined suspicious signals|"
    r"multi[- ]signal email anomaly)\b",
    re.I,
)
_EXPLICIT_MULTI_RE = re.compile(
    r"\b(?:multiple|several|two or more|independent|combined)\b.{0,55}"
    r"\b(?:suspicious indicators?|warning signs?|risk signals?|anomalies|security signals?)\b|"
    r"\b(?:suspicious indicators?|warning signs?|risk signals?|anomalies|security signals?)\b"
    r".{0,55}\b(?:multiple|several|independent|combined|appear together|present together)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"security report|incident report|dashboard|metrics report|health indicators|"
    r"market indicators|performance indicators|quality indicators|"
    r"resolved warning signs|scanner validation report)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "the sender changed and the link is untrusted",
    "authentication failed and the attachment is unexpected",
    "the headers conflict and the destination is suspicious",
    "a low-reputation sender included an unusual file",
    "the message context changed and the sender is unfamiliar",
    "the body is unreadable and the sender address changed",
    "an unusual request arrived through a risky link",
    "the sender behavior changed and the message demands secrecy",
    "this new contact asks about internal systems",
    "the subject is incoherent and the attachment is unverified",
    "authentication is inconsistent and the content cannot be scanned",
    "a suspicious destination accompanies an out-of-process request",
    "the trusted contact behaves differently and uses a new address",
    "the message pressures secrecy and probes internal contacts",
    "multiple independent warning signs appear in this email",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _count(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "multi_indicator_suspicious_email_detected",
        "multiple_suspicious_indicators_detected",
        "combined_suspicious_signals_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("suspicious_indicator_count", "independent_warning_count", "risk_signal_count"):
        count = _count(email_data.get(key))
        if count >= 2:
            return f"mailbox metadata reports {count} independent suspicious indicators"
    for key in (
        "suspicious_classification", "multi_indicator_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner multi-indicator evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "multi_indicator_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a multi-indicator suspicious email"
    if _EXPLICIT_MULTI_RE.search(text):
        return "message explicitly reports multiple independent suspicious indicators"
    return ""


def evaluate_multi_indicator_suspicious_email_rules(
    *, email_data: Mapping, text: str, existing_flags: Collection[str]
) -> list[SecurityRuleHit]:
    components = sorted(_COMPONENT_FLAGS.intersection(existing_flags))
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason and len(components) >= 2:
        reason = "independent subtype signals: " + ", ".join(components)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type15-multi-indicator",
        points=100,
        reason=f"Multi-indicator suspicious email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="multi-indicator-suspicious-email",
    )]
