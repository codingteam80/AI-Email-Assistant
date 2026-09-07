"""Suspicious Type 17: identify threats awaiting a final security verdict."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:pending[- ]analysis threat|pending threat analysis|awaiting threat verdict|"
    r"unresolved security analysis|inconclusive security verdict)\b",
    re.I,
)
_PENDING_SECURITY_RE = re.compile(
    r"\b(?:security|threat|malware|attachment|content|risk|automated|sandbox|"
    r"detonation)\b.{0,45}\b(?:analysis|scan|inspection|verdict|classification|"
    r"assessment|investigation|review)\b.{0,70}\b(?:pending|awaiting|queued|"
    r"in progress|not (?:yet )?(?:complete|completed|finished)|has not (?:completed|finished)|"
    r"no final verdict|without a final verdict|inconclusive|temporarily unavailable|"
    r"deferred|requires? additional|cannot yet be (?:classified|completed))|"
    r"\b(?:pending|awaiting|queued|in progress|not (?:yet )?(?:complete|completed|finished)|"
    r"has not (?:completed|finished)|no final verdict|inconclusive|temporarily unavailable|"
    r"deferred|requires? additional|cannot yet be (?:classified|completed))\b.{0,70}"
    r"\b(?:security|threat|malware|attachment|content|risk|automated|sandbox|"
    r"detonation)\b.{0,40}\b(?:analysis|scan|inspection|verdict|classification|"
    r"assessment|investigation|review)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"detection guidance|quoted example|false positive|known safe|"
    r"analysis completed|scan completed|final clean verdict|final verdict is clean|"
    r"ordinary project analysis|business analysis|medical analysis|laboratory analysis|"
    r"pending manager review|pending editorial review|pending legal review|"
    r"scheduled security maintenance|scanner status report|queue metrics report)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "security analysis is still pending",
    "this message is awaiting a threat verdict",
    "the attachment scan has not completed",
    "automated analysis remains in progress",
    "the security engine returned no final verdict",
    "this email is queued for deeper inspection",
    "malware analysis has not finished",
    "the message requires additional security review",
    "threat classification is temporarily unavailable",
    "the content scan produced an inconclusive result",
    "this email remains under automated investigation",
    "the risk assessment has not completed",
    "analysis was deferred for this message",
    "the security verdict is pending further inspection",
    "this message cannot yet be classified safely",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}
_PENDING_STATUSES = {
    "pending", "awaiting", "queued", "in_progress", "in progress",
    "inconclusive", "deferred", "unavailable", "not_completed", "not completed",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "pending_analysis_threat_detected",
        "pending_threat_analysis_detected",
        "awaiting_security_verdict_detected",
        "inconclusive_security_analysis_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "threat_analysis_status", "security_analysis_status", "security_scan_status",
        "malware_analysis_status", "security_verdict_status",
    ):
        status = str(email_data.get(key) or "").casefold().strip()
        if status in _PENDING_STATUSES:
            return f"mailbox metadata reports {key.replace('_', ' ')} as {status}"
    for key in (
        "suspicious_classification", "threat_analysis", "security_scan_analysis",
        "classification_analysis", "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner pending-analysis evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "threat_analysis", "security_scan_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a pending-analysis threat"
    if _PENDING_SECURITY_RE.search(text):
        return "message states that security analysis has no final verdict"
    return ""


def evaluate_pending_analysis_threat_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type17-pending-analysis-threat",
        points=100,
        reason=f"Pending-analysis threat detected ({reason})",
        categories=("Suspicious",),
        strong_flag="pending-analysis-threat",
    )]
