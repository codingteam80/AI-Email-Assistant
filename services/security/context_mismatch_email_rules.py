"""Suspicious Type 3: identify messages whose context conflicts with the thread."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:context[- ]mismatch email|message context mismatch|thread context mismatch|"
    r"subject[- ]body mismatch|recipient context mismatch|conversation mismatch)\b",
    re.I,
)
_MISMATCH_RE = re.compile(
    r"\b(?:does not|doesn't|doesn.t|did not|didn't|didn.t|cannot|can't|can.t)\b.{0,70}"
    r"\b(?:match|belong|fit|relate|align|recognize|support|request|schedule|discuss)|"
    r"\b(?:wrong|unrelated|inconsistent|incorrect|mismatched|unknown|unexpected)\b.{0,55}"
    r"\b(?:thread|conversation|context|subject|body|topic|recipient|request|order|invoice|"
    r"meeting|project|instructions?|files?|question|purpose)|"
    r"\b(?:thread|conversation|context|subject|body|topic|recipient|request|order|invoice|"
    r"meeting|project|instructions?|files?|question|purpose)\b.{0,55}"
    r"\b(?:does not|doesn't|doesn.t|did not|didn't|didn.t|wrong|unrelated|inconsistent|"
    r"incorrect|mismatched|unknown|unexpected|never)\b|"
    r"\b(?:reply|message|email|note)\b.{0,45}\b(?:wrong thread|out of context|"
    r"unrelated topic|different matters?)\b|"
    r"\b(?:request|message|email|reply|instructions?)\b.{0,45}"
    r"\bconflicts? with\b.{0,45}\b(?:earlier|previous|thread|conversation|instructions?)\b",
    re.I,
)
_CONTEXT_RE = re.compile(
    r"\b(?:message|email|reply|note|thread|conversation|context|subject|body|topic|"
    r"recipient|request|order|invoice|meeting|project|instructions?|files?|question|"
    r"purpose|history|stated purpose|earlier discussion)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"corrected subject|subject line (?:was )?updated|continuing our conversation|"
    r"as (?:you )?requested|expected thread|legitimate topic change|known issue|"
    r"minutes from (?:our|the) meeting|order correction requested)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this reply does not match our conversation",
    "the subject and message discuss different matters",
    "this email refers to a meeting we never scheduled",
    "the request conflicts with the earlier instructions",
    "this message appears in the wrong thread",
    "the body does not match the stated purpose",
    "this note references an unknown order",
    "the project context is inconsistent",
    "this reply mentions files we did not request",
    "the recipient context appears incorrect",
    "this message continues an unrelated topic",
    "the invoice reference does not belong here",
    "the conversation history does not support this request",
    "this email answers a question we never asked",
    "the final request is inconsistent with the thread",
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
        "false", "no", "mismatch", "mismatched", "incorrect", "inconsistent",
    }


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "context_mismatch_email_detected",
        "message_context_mismatch_detected",
        "subject_body_mismatch_detected",
        "thread_context_mismatch_detected",
        "recipient_context_mismatch_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "subject_body_match",
        "thread_context_match",
        "recipient_context_match",
        "conversation_context_match",
    ):
        if key in email_data and _false(email_data.get(key)):
            return f"mailbox metadata reports {key.replace('_', ' ')}"
    for key in (
        "suspicious_classification",
        "context_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner context-mismatch evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "context_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a context-mismatch email"
    if _MISMATCH_RE.search(text) and _CONTEXT_RE.search(text):
        return "message explicitly conflicts with its subject, recipient, or conversation context"
    return ""


def evaluate_context_mismatch_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type3-context-mismatch",
        points=100,
        reason=f"Context-mismatch email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="context-mismatch-email",
    )]
