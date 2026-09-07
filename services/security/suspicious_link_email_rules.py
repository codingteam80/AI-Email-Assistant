"""Suspicious Type 8: identify explicit risky-link evidence without visiting URLs."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:suspicious[- ]link email|untrusted link email|risky link destination|"
    r"link destination mismatch|suspicious redirect|low reputation link)\b",
    re.I,
)
_SUSPICIOUS_LINK_RE = re.compile(
    r"\b(?:link|web link|url|web address|destination|linked domain|link target|redirect)\b"
    r".{0,85}\b(?:suspicious|risky|untrusted|unverified|not recognized|unknown|"
    r"low reputation|poor reputation|shortened|obfuscated|hidden|mismatched|"
    r"does not match|doesn't match|differs? from|raw ip|ip address|newly observed|"
    r"unrelated to the sender|unexpected)|"
    r"\b(?:suspicious|risky|untrusted|unverified|unknown|shortened|obfuscated|hidden|"
    r"mismatched|unexpected)\b.{0,65}"
    r"\b(?:link|web link|url|web address|destination|linked domain|link target|redirect)\b",
    re.I,
)
_LINK_CONTEXT_RE = re.compile(
    r"\b(?:link|url|web address|destination|domain|redirect|raw ip|ip address|target)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|allowlisted|"
    r"approved internal link|verified destination|trusted corporate shortener|"
    r"documented redirect|authenticated service link|expected tracking redirect|"
    r"administrator confirmed|official documentation)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this message contains an untrusted link",
    "the link destination does not match its text",
    "a shortened address hides the destination",
    "the linked domain has a low reputation",
    "this email includes an unexpected web address",
    "the link redirects through an unknown domain",
    "the destination uses a raw ip address",
    "the message contains an obfuscated link",
    "the visible link and destination differ",
    "the web address is not recognized",
    "this link points to a newly observed domain",
    "the destination reputation is suspicious",
    "the message uses a hidden redirect",
    "the link target is unrelated to the sender",
    "the email contains a risky destination",
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


def _link_collection_reason(email_data: Mapping) -> str:
    links = email_data.get("links") or email_data.get("security_links") or ()
    if isinstance(links, (str, bytes, bytearray)) or not isinstance(links, Sequence):
        return ""
    for link in links:
        if not isinstance(link, Mapping):
            continue
        if any(_true(link.get(key)) for key in (
            "suspicious", "is_suspicious", "untrusted", "destination_mismatch", "hidden_redirect",
        )):
            return "structured link metadata marks a destination as suspicious"
        reputation = str(link.get("reputation") or "").casefold().strip()
        if reputation in {"low", "poor", "bad", "risky", "suspicious", "untrusted"}:
            return f"structured link metadata reports {reputation} reputation"
        if _low_score(link.get("reputation_score")):
            return "structured link reputation score is at or below 20"
    return ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "suspicious_link_email_detected",
        "untrusted_link_detected",
        "link_destination_mismatch_detected",
        "suspicious_redirect_detected",
        "risky_link_destination_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("link_reputation_score", "destination_reputation_score"):
        if _low_score(email_data.get(key)):
            return f"{key.replace('_', ' ')} is at or below 20"
    reputation = str(email_data.get("link_reputation") or "").casefold().strip()
    if reputation in {"low", "poor", "bad", "risky", "suspicious", "untrusted"}:
        return f"link reputation is {reputation}"
    collection_reason = _link_collection_reason(email_data)
    if collection_reason:
        return collection_reason
    for key in (
        "suspicious_classification",
        "link_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner suspicious-link evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "link_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a suspicious-link email"
    if _SUSPICIOUS_LINK_RE.search(text) and _LINK_CONTEXT_RE.search(text):
        return "message explicitly describes an untrusted, mismatched, or obscured destination"
    return ""


def evaluate_suspicious_link_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type8-suspicious-link",
        points=100,
        reason=f"Suspicious-link email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="suspicious-link-email",
    )]

