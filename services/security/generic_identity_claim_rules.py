"""Impersonation Type 1: detect generic identity claims from inconsistent channels."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_CLAIM_RE = re.compile(
    r"\b(?:i am|i'm|this is|we are|we're|i represent|we represent|writing on behalf of|"
    r"contacting you on behalf of|speaking for|from the|member of the|acting as|your assigned)\b",
    re.I,
)
_IDENTITY_RE = re.compile(
    r"\b(?:bank|credit union|customer service|security (?:team|department|officer)|fraud (?:team|officer)|"
    r"it (?:administrator|support|department)|system administrator|help desk|support representative|"
    r"tax (?:authority|office|officer)|revenue service|government (?:office|agency|benefits officer|benefits office)|"
    r"hr (?:manager|department|representative)|human resources|payroll (?:office|team|representative)|"
    r"legal counsel|attorney|lawyer|court officer|police officer|law enforcement|"
    r"courier|delivery (?:company|representative|support)|account manager|vendor coordinator|"
    r"supplier representative|university registrar|school administrator|insurance claims officer|"
    r"hospital billing representative|telecom support|social-media moderation team|"
    r"building management|property manager|payment processor|financial agent)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:reply|respond|call|phone|contact|confirm|acknowledge|send|provide|share|update|"
    r"schedule|arrange|return|forward|submit|verify)\b.{0,120}\b(?:case|reference|number|time|"
    r"availability|appointment|notice|request|record|details?|information|document|order|delivery|"
    r"policy|account|device|support|interview|attendance|purchase order|po number|pay period)\b"
    r"|\b(?:please|kindly)\b.{0,100}\b(?:reply|respond|call|contact|confirm|acknowledge|send|"
    r"provide|schedule|verify)\b",
    re.I | re.S,
)
_RISKY_CHANNEL_RE = re.compile(
    r"\b(?:temporary (?:email|address|mailbox)|personal (?:email|address|mailbox)|new email address|"
    r"alternate (?:email|address|mailbox)|different email address|private mailbox|"
    r"official email is unavailable|company email is unavailable|system is down|mailbox issue|"
    r"using my personal account|away from the office)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:generic identity impersonation|false identity claim|fraudulent identity claim|"
    r"authority impersonation|organization impersonation|identity-claim scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|verified official domain|authenticated corporate account|"
    r"confirmed through (?:the )?official directory|no action (?:is )?requested|"
    r"no reply (?:is )?requested|identity verification policy)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:generic identity claim|false identity claim|authority impersonation|"
    r"organization impersonation|identity-claim fraud)\b",
    re.I,
)
_FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "proton.me", "protonmail.com", "mail.com",
}


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "generic_identity_claim_detected", "identity_claim_impersonation_detected",
        "false_identity_claim_detected", "authority_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("identity_analysis", "impersonation_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner generic-identity evidence: {value[:120]}"
    return ""


def _sender_risk(email_data: Mapping) -> bool:
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    reply_address = parseaddr(str(email_data.get("reply_to") or email_data.get("replyTo") or ""))[1]
    sender_domain = sender_address.rpartition("@")[2].casefold()
    reply_domain = reply_address.rpartition("@")[2].casefold()
    evidence = " ".join(str(email_data.get(key) or "") for key in (
        "spam_evidence", "authentication_results", "security_analysis",
    )).casefold()
    free_mail_authority = sender_domain in _FREE_MAIL_DOMAINS and bool(_IDENTITY_RE.search(sender_name))
    reply_mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    auth_or_lookalike = bool(re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|lookalike|typosquat|spoof", evidence))
    return free_mail_authority or reply_mismatch or auth_or_lookalike


def _behavior_reason(email_data: Mapping, value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes a false or impersonated identity claim"
    claim = bool(_CLAIM_RE.search(text))
    identity = bool(_IDENTITY_RE.search(text))
    action = bool(_ACTION_RE.search(text))
    risky_channel = bool(_RISKY_CHANNEL_RE.search(text))
    sender_risk = _sender_risk(email_data)
    if claim and identity and action and (risky_channel or sender_risk):
        return "claimed authority or organization requests action through an inconsistent channel"
    if claim and identity and risky_channel and sender_risk:
        return "authority identity claim is delivered through an unrelated personal or diverted sender"
    return ""


def evaluate_generic_identity_claim_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type1-generic-identity-claim",
        points=100,
        reason=f"Generic identity claim impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="generic-identity-claim-impersonation",
    )]
