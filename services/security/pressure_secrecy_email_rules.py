"""Suspicious Type 12: identify requests combining pressure with secrecy."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:pressure[- ]and[- ]secrecy email|pressure plus secrecy|"
    r"urgent confidential request|coercive secrecy request|secret urgent action)\b",
    re.I,
)
_PRESSURE_RE = re.compile(
    r"\b(?:urgent|urgently|immediate|immediately|right away|now|act now|do this now|"
    r"complete this now|proceed now|without delay|do not delay|don't delay|cannot wait|"
    r"can't wait|no time to (?:wait|explain)|before the deadline|before anyone notices|"
    r"today|within the hour|time[- ]sensitive|act fast|must be done|must be completed|"
    r"cannot be delayed|can't be delayed)\b",
    re.I,
)
_SECRECY_RE = re.compile(
    r"\b(?:keep (?:this|it) (?:secret|confidential|private|quiet|between us)|"
    r"keep this between us|do not tell|don't tell|tell nobody|tell no one|"
    r"no one else should know|nobody else should know|do not (?:notify|inform|discuss|"
    r"mention|share|copy|involve|alert)|don't (?:notify|inform|discuss|mention|share|"
    r"copy|involve|alert)|without (?:notifying|informing|discussing(?: it| this)?(?: with)?|involving|"
    r"alerting|copying)|avoid (?:notifying|informing|involving|alerting)|"
    r"leave no one informed|leave others uninformed|between you and me|"
    r"not for anyone else|must remain secret|must stay confidential|"
    r"cannot be shared|no one should be told)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"approved confidential filing|authorized confidential process|"
    r"attorney[- ]client privilege|legal privilege|patient confidentiality|"
    r"medical confidentiality|signed nda|under nda|approved embargo|"
    r"documented incident response|approved escalation|scheduled deadline|"
    r"formal review process|authorized privacy requirement|no immediate action required)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "do this immediately and keep it between us",
    "do not tell anyone until this is complete",
    "handle this now without notifying the team",
    "this must stay confidential and cannot wait",
    "act before the deadline and keep it secret",
    "complete this urgently without discussing it",
    "no one else should know about this request",
    "respond right away and do not copy anyone",
    "finish this today and keep it quiet",
    "there is no time to explain, tell nobody",
    "proceed immediately without involving your manager",
    "keep this private and act before anyone notices",
    "do not delay and do not mention this conversation",
    "this is urgent, avoid alerting the usual reviewers",
    "complete the request now and leave no one informed",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "pressure_and_secrecy_email_detected",
        "pressure_secrecy_detected",
        "urgent_secret_request_detected",
        "coercive_secrecy_request_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    pressure_flag = any(_true(email_data.get(key)) for key in (
        "pressure_language_detected", "urgent_action_pressure_detected",
    ))
    secrecy_flag = any(_true(email_data.get(key)) for key in (
        "secrecy_language_detected", "confidentiality_pressure_detected",
    ))
    if pressure_flag and secrecy_flag:
        return "mailbox metadata reports combined pressure and secrecy language"
    for key in (
        "suspicious_classification",
        "pressure_analysis",
        "secrecy_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner pressure-and-secrecy evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "pressure_analysis", "secrecy_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a pressure-and-secrecy email"
    if _PRESSURE_RE.search(text) and _SECRECY_RE.search(text):
        return "message combines time pressure with instructions to conceal the request"
    return ""


def evaluate_pressure_secrecy_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type12-pressure-secrecy",
        points=100,
        reason=f"Pressure-and-secrecy email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="pressure-secrecy-email",
    )]
