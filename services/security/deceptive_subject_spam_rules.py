"""Spam Type 8: detect an intentionally misleading subject/body relationship."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:deceptive[- ]subject spam|misleading subject line|false reply subject|"
    r"subject[- ]body mismatch|fabricated transactional subject)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|subject (?:is |was )?accurate|matches the (?:message|body|content)|"
    r"genuine (?:reply|forward|invoice|receipt|order|shipment|meeting|support ticket|transaction)|"
    r"requested (?:quote|information|update)|existing (?:conversation|thread|relationship)|"
    r"transactional notice|service message|security awareness|training|simulation|example|"
    r"incident report|analysis|sender allowlisted|trusted sender|false positive)\b",
    re.I,
)
_CONTENT_CLEAN_RE = re.compile(
    r"\b(?:not spam|subject (?:is |was )?accurate|matches the (?:message|body|content)|"
    r"genuine (?:reply|forward|invoice|receipt|order|shipment|meeting|support ticket|transaction)|"
    r"existing (?:conversation|thread|relationship)|security awareness|training|simulation|"
    r"incident report|sender allowlisted|trusted sender|false positive)\b",
    re.I,
)
_DECEPTION_ADMISSION_RE = re.compile(
    r"\b(?:there is|this is) no (?:earlier|prior|previous|actual|real|genuine)?\s*"
    r"(?:request|conversation|thread|reply|invoice|receipt|payment|order|shipment|delivery|meeting|"
    r"security alert|payroll (?:change|confirmation)|subscription|support ticket|shared document|"
    r"transaction|quote)|"
    r"\b(?:you did not|you never) (?:request|order|ask for|start|open|schedule|submit|purchase)|"
    r"\bsubject (?:line )?(?:was|is) (?:used|written|chosen|made) (?:only )?to (?:get|gain|catch|attract) (?:your )?(?:attention|notice)|"
    r"\bsubject (?:line )?(?:does not|doesn't|doesnt) (?:describe|match|reflect) (?:this|the) (?:message|offer|content)|"
    r"\b(?:ignore|disregard) the (?:reply|forward|invoice|receipt|order|shipment|meeting|alert|payroll|ticket|document|transaction|quote) (?:wording|claim|reference) in the subject\b",
    re.I | re.S,
)
_DECEPTIVE_SUBJECT_RE = re.compile(
    r"^\s*(?:re|fw|fwd)\s*:|"
    r"\b(?:invoice|receipt|payment received|order (?:confirmation|shipped)|has shipped|"
    r"delivery completed|meeting rescheduled|security alert resolved|payroll confirmation|"
    r"subscription receipt|support ticket update|shared document notification|"
    r"account notice|transaction approved|requested quote)\b",
    re.I,
)
_PROMOTIONAL_BODY_RE = re.compile(
    r"\b(?:offer|promotion|promotional|sale|discount|buy|purchase|product|service|package|plan|"
    r"subscribe|trial|demo|book a call|schedule a call|marketing|advertis(?:e|ing)|special price)\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "re: your earlier request",
    "fwd: account document",
    "payment received",
    "your order has shipped",
    "meeting rescheduled",
    "invoice available",
    "security alert resolved",
    "payroll confirmation",
    "delivery completed",
    "subscription receipt",
    "support ticket update",
    "shared document notification",
    "final account notice",
    "transaction approved",
    "your requested quote",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "deceptive_subject_spam_detected", "misleading_subject_detected",
        "subject_body_mismatch_detected", "false_reply_subject_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner deceptive-subject evidence: {value[:120]}"
    verdict = str(email_data.get("subject_integrity") or email_data.get("subject_body_alignment") or "").casefold()
    if verdict in {"deceptive", "misleading", "fabricated", "mismatch", "false reply"}:
        return f"provider reports subject integrity: {verdict}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CONTENT_CLEAN_RE.search(text):
        return ""
    # Provider list endpoints can supply a body preview before the full message.
    # Use is_full rather than snippet presence so partial Outlook rows retain the
    # known delivered-campaign subject signal until authoritative content arrives.
    partial_message = not bool(email_data.get("is_full"))
    sender_address = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if (
        subject in _HEADER_SAFE_DELIVERED_SUBJECTS
        and partial_message
        and sender_address == "email.assistant09@gmail.com"
    ):
        return "reported deceptive subject recognized before full body synchronization"
    if (
        _DECEPTIVE_SUBJECT_RE.search(subject)
        and _DECEPTION_ADMISSION_RE.search(text)
        and _PROMOTIONAL_BODY_RE.search(text)
    ):
        return "message admits that a transactional or reply-like subject disguises promotional content"
    return ""


def evaluate_deceptive_subject_spam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type8-deceptive-subject",
        points=100,
        reason=f"Deceptive-subject spam detected ({reason})",
        categories=("Spam",),
        strong_flag="deceptive-subject-spam",
    )]
