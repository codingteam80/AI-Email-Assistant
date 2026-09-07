"""Suspicious Type 16: identify email associated with a suspicious campaign."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:campaign[- ]associated email|suspicious campaign association|"
    r"known campaign match|threat cluster association|coordinated email cluster)\b",
    re.I,
)
_CAMPAIGN_ASSOCIATION_RE = re.compile(
    r"\b(?:match(?:es)?|linked to|associated with|belongs to|part of|resembles?|"
    r"shares? (?:infrastructure|indicators?|sender|wording|template|fingerprint) with|"
    r"seen in|appears? across|reported by)\b.{0,90}"
    r"\b(?:known suspicious campaign|active suspicious campaign|suspicious email campaign|"
    r"known campaign|flagged messages?|suspicious messages?|earlier incidents?|"
    r"coordinated email wave|ongoing campaign|flagged cluster|suspicious cluster|prior suspicious mail|"
    r"threat cluster|recurring suspicious campaign|related suspicious emails?)\b|"
    r"\b(?:known suspicious campaign|active suspicious campaign|suspicious email campaign|"
    r"known campaign|flagged messages?|suspicious messages?|earlier incidents?|"
    r"coordinated email wave|ongoing campaign|flagged cluster|suspicious cluster|prior suspicious mail|"
    r"threat cluster|recurring suspicious campaign|related suspicious emails?)\b"
    r".{0,90}\b(?:match(?:es)?|linked|associated|belongs|shares?|seen|appears?|reported|"
    r"same sender|same domain|same template|same fingerprint|same infrastructure)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"authorized marketing campaign|approved marketing campaign|promotional campaign|"
    r"newsletter campaign|customer campaign|internal communications campaign|"
    r"fundraising campaign|public awareness campaign|approved outreach campaign|"
    r"incident report|campaign report|historical analysis|threat research report)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this message matches a known suspicious campaign",
    "the sender is linked to an active email campaign",
    "the subject pattern matches previously flagged messages",
    "this email shares infrastructure with a suspicious campaign",
    "the message template was seen in earlier incidents",
    "the sender domain appears across related suspicious emails",
    "this message belongs to a coordinated email wave",
    "the tracking identifiers match a known campaign",
    "similar messages were reported by multiple recipients",
    "the delivery pattern matches an ongoing campaign",
    "this email shares indicators with a flagged cluster",
    "the message fingerprint matches prior suspicious mail",
    "the sender and wording match a known campaign",
    "this email is associated with a monitored threat cluster",
    "the message resembles a recurring suspicious campaign",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "campaign_associated_email_detected",
        "suspicious_campaign_association_detected",
        "known_campaign_match_detected",
        "threat_cluster_association_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    campaign_id = str(email_data.get("suspicious_campaign_id") or "").strip()
    association = str(email_data.get("campaign_association_status") or "").casefold().strip()
    if campaign_id and association in {"matched", "associated", "linked", "confirmed"}:
        return "mailbox metadata links the message to a suspicious campaign identifier"
    for key in (
        "suspicious_classification", "campaign_analysis", "cluster_analysis",
        "classification_analysis", "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner campaign-association evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "campaign_analysis", "cluster_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a campaign-associated email"
    if _CAMPAIGN_ASSOCIATION_RE.search(text):
        return "message is explicitly associated with a suspicious campaign or cluster"
    return ""


def evaluate_campaign_associated_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type16-campaign-associated",
        points=100,
        reason=f"Campaign-associated email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="campaign-associated-email",
    )]
