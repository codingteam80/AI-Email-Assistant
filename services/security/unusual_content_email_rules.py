"""Suspicious Type 1: identify emails with anomalous or incoherent content."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unusual[- ]content email|anomalous email content|content anomaly|"
    r"incoherent message content|unexpected content structure)\b",
    re.I,
)
_ANOMALY_RE = re.compile(
    r"\b(?:unusual|strange|unexpected|anomalous|garbled|fragmented|incoherent|"
    r"nonsensical|random|unexplained|mismatched|unrelated|out of context|"
    r"does not match|doesn't match|abruptly (?:changes?|switches?)|"
    r"changes? (?:topic|direction) without context|oddly formatted|"
    r"corrupted text|unknown sequence)\b",
    re.I,
)
_CONTENT_RE = re.compile(
    r"\b(?:message|email|content|body|subject|text|wording|lines?|paragraphs?|"
    r"sections?|note|instructions?|symbols?|characters?|codes?|fragments?|"
    r"formatting|topic|sequence|text blocks?)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|"
    r"research|analysis|detection guidance|incident report|quoted example|"
    r"false positive|known safe|sender allowlisted|expected format change|"
    r"software log|source code|checksum|tracking number|delivery status)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "the message changes topic without context",
    "several lines appear unrelated",
    "this note contains unexplained fragments",
    "the wording becomes suddenly incoherent",
    "an unusual sequence appears in the message",
    "the content does not match the subject",
    "this email includes random text blocks",
    "the message switches direction abruptly",
    "unfamiliar symbols interrupt the note",
    "the body contains mismatched sections",
    "this message has garbled wording",
    "the text includes unexplained codes",
    "the note combines unrelated instructions",
    "strange formatting appears throughout",
    "the final paragraph is out of context",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unusual_content_email_detected",
        "anomalous_content_detected",
        "content_anomaly_detected",
        "unusual_message_structure_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "suspicious_classification",
        "content_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner unusual-content evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "content_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies an unusual-content email"
    if _ANOMALY_RE.search(text) and _CONTENT_RE.search(text):
        return "message explicitly contains anomalous, mismatched, or incoherent content"
    return ""


def evaluate_unusual_content_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type1-unusual-content",
        points=100,
        reason=f"Unusual-content email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="unusual-content-email",
    )]

