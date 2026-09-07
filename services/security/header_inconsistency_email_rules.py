"""Suspicious Type 6: identify contradictions across message and routing headers."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:header[- ]inconsistency email|mail header inconsistency|"
    r"conflicting message headers|routing header mismatch|sender header conflict|"
    r"header identity mismatch)\b",
    re.I,
)
_HEADER_INCONSISTENCY_RE = re.compile(
    r"\b(?:from|reply-to|reply address|return-path|envelope sender|message-id|"
    r"received path|routing headers?|sender headers?|header dates?|header sequence|"
    r"mail headers?|message headers?|headers?|header information|sender domain)\b.{0,80}"
    r"\b(?:do(?:es)? not match|doesn't match|don't match|"
    r"differs?(?:\s+\w+){0,3}\s+from|conflicts? with|inconsistent|"
    r"conflicting|mismatch(?:ed)?|malformed|out of order|multiple|duplicate|changes?|"
    r"internally inconsistent|unexpected)\b|"
    r"\b(?:do(?:es)? not match|doesn't match|don't match|"
    r"differs?(?:\s+\w+){0,3}\s+from|conflicts? with|inconsistent|"
    r"conflicting|mismatch(?:ed)?|malformed|out of order|multiple|duplicate|unexpected|changes?)\b"
    r".{0,80}\b(?:from|reply-to|reply address|return-path|envelope sender|message-id|"
    r"received path|routing headers?|sender headers?|header dates?|header sequence|"
    r"mail headers?|message headers?|headers?|header information|sender domain)\b",
    re.I,
)
_HEADER_CONTEXT_RE = re.compile(
    r"\b(?:headers?|from|reply-to|reply address|return-path|envelope sender|message-id|"
    r"received path|routing|sender domain|sender identity|header dates?|header sequence)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"documented forwarding service|authenticated mailing list|approved relay|"
    r"verified ticketing system|expected reply handling|confirmed mail gateway|"
    r"standards documentation|administrator confirmed)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "the from and reply-to headers do not match",
    "the return-path differs from the visible sender",
    "the message-id domain is inconsistent",
    "this email contains conflicting sender headers",
    "the routing headers do not match the sender",
    "multiple from headers appear in this message",
    "the header dates are inconsistent",
    "the reply address conflicts with the from address",
    "the envelope sender differs unexpectedly",
    "the received path is inconsistent with the domain",
    "this message contains a malformed sender header",
    "the header sequence is out of order",
    "the sender domain changes across the headers",
    "the mail headers contain conflicting identities",
    "the header information is internally inconsistent",
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
        "false", "no", "mismatch", "mismatched", "inconsistent", "conflicting",
    }


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "header_inconsistency_email_detected",
        "mail_header_inconsistency_detected",
        "conflicting_headers_detected",
        "routing_header_anomaly_detected",
        "sender_header_conflict_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "headers_consistent",
        "sender_headers_consistent",
        "routing_headers_consistent",
        "header_identity_consistent",
    ):
        if key in email_data and _false(email_data.get(key)):
            return f"mailbox metadata reports {key.replace('_', ' ')}"
    for key in (
        "suspicious_classification",
        "header_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner header-inconsistency evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "header_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a header-inconsistency email"
    if _HEADER_INCONSISTENCY_RE.search(text) and _HEADER_CONTEXT_RE.search(text):
        return "message explicitly describes conflicting sender, identity, or routing headers"
    return ""


def evaluate_header_inconsistency_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type6-header-inconsistency",
        points=100,
        reason=f"Header-inconsistency email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="header-inconsistency-email",
    )]
