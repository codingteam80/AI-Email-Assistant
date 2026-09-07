"""Impersonation Type 2: detect protected display names on unrelated sender domains."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_BRAND_DOMAINS = {
    "microsoft": ("microsoft.com", "office.com", "microsoftonline.com"),
    "google": ("google.com",),
    "apple": ("apple.com",),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.co.uk"),
    "docusign": ("docusign.com", "docusign.net"),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "ups": ("ups.com",),
    "netflix": ("netflix.com",),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
}
_ROLE_DISPLAY_RE = re.compile(
    r"\b(?:it help desk|it support|security team|support team|hr department|payroll office|"
    r"accounts payable|billing department|delivery support|tax office|title company|"
    r"property settlement team|account protection team|system administrator)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:reply|respond|call|phone|contact|confirm|acknowledge|send|provide|share|update|"
    r"schedule|arrange|return|forward|submit|review|open|view|verify)\b.{0,130}\b(?:case|reference|"
    r"number|time|availability|appointment|notice|request|record|details?|information|document|"
    r"order|delivery|account|device|support|interview|attendance|license|envelope|folder|"
    r"pay period|transaction)\b"
    r"|\b(?:please|kindly)\b.{0,100}\b(?:reply|respond|call|contact|confirm|acknowledge|send|"
    r"provide|schedule|review|verify)\b",
    re.I | re.S,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:display[- ]name impersonation|forged display name|spoofed display name|"
    r"brand display-name spoofing|display-name deception)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|verified official domain|authenticated corporate account|"
    r"confirmed through (?:the )?official directory|no action (?:is )?requested|"
    r"display-name spoofing awareness)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:display[- ]name impersonation|forged display name|spoofed display name|"
    r"brand-name impersonation|display-name deception)\b",
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
        "display_name_impersonation_detected", "forged_display_name_detected",
        "spoofed_display_name_detected", "brand_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("display_name_analysis", "impersonation_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner display-name evidence: {value[:120]}"
    return ""


def _display_identity_risk(email_data: Mapping) -> tuple[bool, str]:
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    display = _canonical_text(sender_name).casefold()
    domain = sender_address.rpartition("@")[2].casefold()
    reply_address = parseaddr(str(email_data.get("reply_to") or email_data.get("replyTo") or ""))[1]
    reply_domain = reply_address.rpartition("@")[2].casefold()
    evidence = " ".join(str(email_data.get(key) or "") for key in (
        "spam_evidence", "authentication_results", "security_analysis",
    )).casefold()
    for brand, official_domains in _BRAND_DOMAINS.items():
        if brand not in display:
            continue
        aligned = any(domain == official or domain.endswith("." + official) for official in official_domains)
        if domain and not aligned:
            return True, f"display name claims {brand} but sender domain is {domain}"
    role = bool(_ROLE_DISPLAY_RE.search(display))
    reply_mismatch = bool(domain and reply_domain and domain != reply_domain)
    auth_or_lookalike = bool(re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|lookalike|typosquat|spoof", evidence))
    if role and (domain in _FREE_MAIL_DOMAINS or reply_mismatch or auth_or_lookalike):
        return True, "trusted departmental display name uses an unrelated or diverted sender"
    return False, ""


def _behavior_reason(email_data: Mapping, value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes display-name impersonation"
    risky, identity_reason = _display_identity_risk(email_data)
    if risky and _ACTION_RE.search(text):
        return identity_reason
    return ""


def evaluate_display_name_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type2-display-name",
        points=100,
        reason=f"Display-name impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="display-name-impersonation-type2",
    )]
