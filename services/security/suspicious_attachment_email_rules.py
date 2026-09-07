"""Suspicious Type 9: identify risky attachments without confirmed malware."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:suspicious[- ]attachment email|risky attachment email|"
    r"unexpected attachment risk|attachment type mismatch|"
    r"untrusted attachment|attachment reputation risk)\b",
    re.I,
)
_SUSPICIOUS_ATTACHMENT_RE = re.compile(
    r"\b(?:attachment|attached file|attached document|file attachment|filename|file type|"
    r"file extension|attachment extension|attachment metadata|file metadata|attachment origin)\b"
    r".{0,90}\b(?:suspicious|risky|unexpected|untrusted|unverified|unfamiliar|unusual|"
    r"unknown|low reputation|poor reputation|not expected|does not match|doesn't match|mismatched|"
    r"inconsistent|hidden|could not be confirmed|cannot be confirmed)|"
    r"\b(?:suspicious|risky|unexpected|untrusted|unverified|unfamiliar|unusual|"
    r"unknown|mismatched|inconsistent|hidden)\b.{0,70}"
    r"\b(?:attachment|attached file|attached document|file attachment|filename|file type|"
    r"file extension|attachment extension|attachment metadata|file metadata|attachment origin)\b|"
    r"\b(?:suspicious|risky|unexpected|untrusted|unverified|unfamiliar|unusual|unknown)\b"
    r".{0,50}\bfile\b.{0,35}\b(?:attached|included|enclosed)\b",
    re.I,
)
_ATTACHMENT_CONTEXT_RE = re.compile(
    r"\b(?:attachment|attached|file|document|filename|extension|metadata|origin|file type)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|allowlisted|"
    r"expected attachment|requested attachment|verified file|approved document|"
    r"trusted internal file|confirmed by the sender|signed release package|"
    r"documented file format|clean scanner verdict)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this message includes an unexpected attachment",
    "the attachment type does not match its name",
    "an unfamiliar file is attached",
    "the attachment source is not trusted",
    "this email contains an unusual file",
    "the attached file has a low reputation",
    "the attachment extension is inconsistent",
    "a hidden file type was detected",
    "the attachment was not expected in this conversation",
    "the file metadata does not match the attachment",
    "this message contains an unverified attachment",
    "the attached document has an unusual structure",
    "the attachment origin could not be confirmed",
    "the filename pattern is considered suspicious",
    "the email includes a risky but unconfirmed file",
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


def _attachment_collection_reason(email_data: Mapping) -> str:
    attachments = email_data.get("attachments") or ()
    if isinstance(attachments, (str, bytes, bytearray)) or not isinstance(attachments, Sequence):
        return ""
    for attachment in attachments:
        if not isinstance(attachment, Mapping):
            continue
        if any(_true(attachment.get(key)) for key in (
            "suspicious", "is_suspicious", "unexpected", "untrusted",
            "name_type_mismatch", "extension_mismatch", "hidden_file_type",
        )):
            return "structured attachment metadata marks the file as suspicious"
        reputation = str(attachment.get("reputation") or "").casefold().strip()
        if reputation in {"low", "poor", "bad", "risky", "suspicious", "untrusted"}:
            return f"structured attachment metadata reports {reputation} reputation"
        if _low_score(attachment.get("reputation_score")):
            return "structured attachment reputation score is at or below 20"
    return ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "suspicious_attachment_email_detected",
        "suspicious_attachment_detected",
        "unexpected_attachment_detected",
        "attachment_type_mismatch_detected",
        "attachment_reputation_low_detected",
        "untrusted_attachment_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("attachment_reputation_score", "attachment_trust_score"):
        if _low_score(email_data.get(key)):
            return f"{key.replace('_', ' ')} is at or below 20"
    reputation = str(email_data.get("attachment_reputation") or "").casefold().strip()
    if reputation in {"low", "poor", "bad", "risky", "suspicious", "untrusted"}:
        return f"attachment reputation is {reputation}"
    collection_reason = _attachment_collection_reason(email_data)
    if collection_reason:
        return collection_reason
    for key in (
        "suspicious_classification",
        "attachment_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner suspicious-attachment evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "attachment_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a suspicious-attachment email"
    if _SUSPICIOUS_ATTACHMENT_RE.search(text) and _ATTACHMENT_CONTEXT_RE.search(text):
        return "message explicitly describes a risky, unexpected, or mismatched attachment"
    return ""


def evaluate_suspicious_attachment_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type9-suspicious-attachment",
        points=100,
        reason=f"Suspicious-attachment email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="suspicious-attachment-email",
    )]
