"""Suspicious Type 11: identify atypical or out-of-process requests."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unusual[- ]request email|atypical request email|out[- ]of[- ]process request|"
    r"unexpected action request|request outside normal workflow)\b",
    re.I,
)
_UNUSUAL_REQUEST_RE = re.compile(
    r"\b(?:unusual|atypical|unfamiliar|unexpected|abnormal|irregular|unrecognized|"
    r"out[- ]of[- ]process|unrelated)\b.{0,75}\b(?:request|action|task|instruction|procedure|"
    r"workflow|method|channel|process|duty|responsibilit(?:y|ies))\b|"
    r"\b(?:request|action|task|instruction|procedure|workflow|method|channel|process|"
    r"duty|responsibilit(?:y|ies))\b.{0,75}\b(?:unusual|atypical|unfamiliar|"
    r"unexpected|abnormal|irregular|unrecognized|out[- ]of[- ]process|unrelated)\b|"
    r"\b(?:outside|beyond)\b.{0,45}\b(?:normal|usual|standard|approved|assigned)\b"
    r".{0,35}\b(?:process|workflow|procedure|role|duties|responsibilities)\b|"
    r"\b(?:not|isn't|isn.t)\b.{0,30}\b(?:normally|usually|typically)\b.{0,55}"
    r"\b(?:request|ask|perform|handle|do|use|follow)\b|"
    r"\b(?:never|have not|haven't|haven.t)\b.{0,45}\b(?:requested|performed|used|"
    r"handled|followed|done)\b.{0,35}\bbefore\b|"
    r"\b(?:bypass|skip|avoid|make an exception to)\b.{0,45}\b(?:normal|usual|"
    r"standard|approved)\b.{0,30}\b(?:process|workflow|procedure|review|channel)\b|"
    r"\b(?:does not|doesn't|doesn.t)\b.{0,35}\b(?:align|fit|belong)\b.{0,45}"
    r"\b(?:role|duties|responsibilities|normal process|usual work)\b|"
    r"\b(?:request|action|task|instruction)\b.{0,35}\b(?:is not|isn't|isn.t)\b"
    r".{0,35}\b(?:part of|within)\b.{0,30}\b(?:your role|your duties|normal work)\b|"
    r"\b(?:instructions?|procedure|workflow|method)\b.{0,30}\b(?:differs? from|"
    r"deviates? from)\b.{0,30}\b(?:normal|usual|standard|approved)\b",
    re.I,
)
_REQUEST_CONTEXT_RE = re.compile(
    r"\b(?:request|ask|action|task|instruction|procedure|workflow|method|channel|"
    r"process|role|duty|duties|responsibility|responsibilities|perform|handle|"
    r"complete|follow|use|bypass|exception)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"approved process change|approved workflow change|authorized exception|"
    r"documented exception|documented procedure|formally approved|manager approved|"
    r"change request approved|scheduled process migration|standard operating procedure|"
    r"as previously requested|within your assigned role|routine request)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this request is outside our normal process",
    "please perform an action we have never used before",
    "use a different procedure than usual",
    "i am asking you to bypass the usual workflow",
    "this task is unrelated to your role",
    "the requested action is not part of your duties",
    "complete an unfamiliar request",
    "handle this request through an unusual channel",
    "i need you to make an exception to the standard process",
    "the instructions differ from normal procedure",
    "this request falls outside the approved workflow",
    "please take an action you do not normally perform",
    "the request does not align with your responsibilities",
    "use an unrecognized method for this task",
    "this action is unusual for our working relationship",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unusual_request_email_detected",
        "unusual_request_detected",
        "atypical_request_detected",
        "out_of_process_request_detected",
        "unexpected_action_request_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "suspicious_classification",
        "request_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner unusual-request evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "request_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies an unusual-request email"
    if _UNUSUAL_REQUEST_RE.search(text) and _REQUEST_CONTEXT_RE.search(text):
        return "message explicitly requests an atypical or out-of-process action"
    return ""


def evaluate_unusual_request_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type11-unusual-request",
        points=100,
        reason=f"Unusual-request email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="unusual-request-email",
    )]
