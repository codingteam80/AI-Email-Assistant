"""Suspicious Type 10: identify content that security inspection cannot parse."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unscannable[- ]content email|content scan failure|unreadable email content|"
    r"unsupported content encoding|content extraction failure|"
    r"incomplete content inspection)\b",
    re.I,
)
_UNSCANNABLE_RE = re.compile(
    r"\b(?:content|message body|email body|message content|attachment content|"
    r"embedded content|embedded data|protected section|message section|scanner|"
    r"security scan|inspection|content format|encoding)\b.{0,95}"
    r"\b(?:could not be scanned|cannot be scanned|could not inspect|cannot inspect|"
    r"could not be inspected|cannot be inspected|could not be parsed|cannot be parsed|"
    r"could not extract|cannot extract|could not be extracted|cannot be extracted|"
    r"could not be decoded|cannot be decoded|unscannable|unreadable|encrypted|corrupted|"
    r"unsupported|incomplete|partially available|inspection failure|scan failure|"
    r"cannot be analyzed|could not be analyzed)|"
    r"\b(?:unscannable|unreadable|encrypted|corrupted|unsupported|incomplete|"
    r"partially available)\b.{0,75}"
    r"\b(?:content|message body|email body|message content|attachment content|"
    r"embedded content|embedded data|protected section|message section|inspection|"
    r"content format|encoding)\b",
    re.I,
)
_CONTENT_CONTEXT_RE = re.compile(
    r"\b(?:content|body|message|email|attachment|embedded|section|scanner|scan|inspection|"
    r"format|encoding|data|extract|decode|parse|analy[sz]e)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"scan completed successfully|content fully scanned|supported format|"
    r"decryption key supplied|verified parser update|expected partial preview|"
    r"trusted encrypted backup|administrator confirmed|clean scanner verdict)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "part of this message could not be scanned",
    "the email content is encrypted and unreadable",
    "the scanner could not inspect the message body",
    "an unsupported encoding prevents inspection",
    "the attachment content could not be parsed",
    "the message contains unreadable sections",
    "the security scan ended with incomplete content",
    "the email body is corrupted",
    "the scanner could not extract the embedded content",
    "a protected section could not be inspected",
    "the message content is only partially available",
    "the content format is unsupported",
    "the scanner reported an inspection failure",
    "embedded data could not be decoded",
    "the email contains content that cannot be analyzed",
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
        "false", "no", "unscannable", "unreadable", "unsupported", "failed",
    }


def _attachment_collection_reason(email_data: Mapping) -> str:
    attachments = email_data.get("attachments") or ()
    if isinstance(attachments, (str, bytes, bytearray)) or not isinstance(attachments, Sequence):
        return ""
    for attachment in attachments:
        if not isinstance(attachment, Mapping):
            continue
        if any(_true(attachment.get(key)) for key in (
            "unscannable", "unreadable", "parse_error", "extraction_failed",
            "unsupported_encoding", "scan_failed",
        )):
            return "structured attachment metadata reports an inspection failure"
        status = str(attachment.get("scan_status") or "").casefold().strip()
        if status in {"unscannable", "unreadable", "unsupported", "failed", "incomplete"}:
            return f"structured attachment scan status is {status}"
        if _true(attachment.get("scan_attempted")) and _false(attachment.get("content_available")):
            return "attachment scan was attempted but content was unavailable"
    return ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unscannable_content_email_detected",
        "unscannable_content_detected",
        "content_scan_failed",
        "content_unreadable_detected",
        "unsupported_content_encoding_detected",
        "content_extraction_failed",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("content_scannable", "content_readable", "content_extractable"):
        if key in email_data and _false(email_data.get(key)):
            return f"mailbox metadata reports {key.replace('_', ' ')}"
    status = str(email_data.get("content_scan_status") or "").casefold().strip()
    if status in {"unscannable", "unreadable", "unsupported", "failed", "incomplete"}:
        return f"content scan status is {status}"
    collection_reason = _attachment_collection_reason(email_data)
    if collection_reason:
        return collection_reason
    for key in (
        "suspicious_classification",
        "content_scan_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner unscannable-content evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "content_scan_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies an unscannable-content email"
    if _UNSCANNABLE_RE.search(text) and _CONTENT_CONTEXT_RE.search(text):
        return "message explicitly states that content could not be scanned, parsed, or decoded"
    return ""


def evaluate_unscannable_content_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type10-unscannable-content",
        points=100,
        reason=f"Unscannable-content email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="unscannable-content-email",
    )]
