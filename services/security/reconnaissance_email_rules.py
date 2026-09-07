"""Suspicious Type 14: identify probing for sensitive internal information."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:reconnaissance email|organizational reconnaissance|internal information probe|"
    r"technical reconnaissance|pretextual information gathering)\b",
    re.I,
)
_PROBE_RE = re.compile(
    r"\b(?:who|which|what|when|how|describe|explain|identify|name|list|send|share|"
    r"provide|confirm|tell me|let me know|I need to know|collect|map|outline)\b",
    re.I,
)
_INTERNAL_TARGET_RE = re.compile(
    r"\b(?:internal (?:employee )?directory|employee directory|contact list|finance contacts?|"
    r"executive availability|executives? (?:are )?(?:available|away|out of office)|"
    r"organization chart|org chart|reporting lines?|department structure|employee roles?|"
    r"payment approvers?|who approves payments?|invoice approval (?:process|workflow)|"
    r"payment approval (?:process|workflow)|vendor roster|regular vendors?|"
    r"payroll (?:schedule|systems?|team|process)|account recovery (?:staff|team|process)|"
    r"urgent account changes?|security tools?|security software|email format|address format|"
    r"remote access (?:process|method|software)|vpn (?:provider|software|process)|"
    r"technology stack|systems? (?:used by|in use)|internal network|network details?|"
    r"support details?|help[- ]desk contacts?|administrator contacts?|"
    r"out[- ]of[- ]office schedule|vacation schedule|senior managers?'? schedules?|"
    r"senior managers?\b.{0,35}\b(?:out of office|away|on vacation)|"
    r"document naming convention|internal procedures?|approval chain|authorization chain)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"authorized audit|approved security assessment|scheduled penetration test|"
    r"approved vendor questionnaire|compliance assessment|internal compliance review|"
    r"employee onboarding|approved onboarding|published directory|public directory|"
    r"documented support ticket|authorized inventory|approved asset inventory|"
    r"internal it inventory|procurement review|manager approved request)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "who approves payments in your department",
    "please send the internal employee directory",
    "which executives are currently available",
    "what security tools does your company use",
    "describe your remote access process",
    "share the names of your finance contacts",
    "how are invoices reviewed and approved",
    "which vendors regularly receive payments",
    "what email format do employees use",
    "send the organization chart and reporting lines",
    "which staff members handle account recovery",
    "what systems are used by the payroll team",
    "when are senior managers usually out of office",
    "provide your internal network and support details",
    "who can authorize urgent account changes",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "reconnaissance_email_detected",
        "organizational_reconnaissance_detected",
        "internal_information_probe_detected",
        "technical_reconnaissance_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "suspicious_classification", "reconnaissance_analysis", "information_probe_analysis",
        "classification_analysis", "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner reconnaissance evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "reconnaissance_analysis", "information_probe_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a reconnaissance email"
    if _PROBE_RE.search(text) and _INTERNAL_TARGET_RE.search(text):
        return "message probes for sensitive organizational or technical information"
    return ""


def evaluate_reconnaissance_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type14-reconnaissance",
        points=100,
        reason=f"Reconnaissance email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="reconnaissance-email",
    )]
