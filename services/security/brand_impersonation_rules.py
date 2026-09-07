"""Impersonation Type 4: detect protected-brand impersonation."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_BRAND_DOMAINS = {
    "microsoft": ("microsoft.com", "office.com", "microsoftonline.com"),
    "google": ("google.com",), "apple": ("apple.com",), "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.co.uk"), "docusign": ("docusign.com", "docusign.net"),
    "fedex": ("fedex.com",), "dhl": ("dhl.com",), "ups": ("ups.com",),
    "netflix": ("netflix.com",), "dropbox": ("dropbox.com",), "adobe": ("adobe.com",),
    "facebook": ("facebook.com", "meta.com"), "instagram": ("instagram.com", "meta.com"),
    "linkedin": ("linkedin.com",), "zoom": ("zoom.us", "zoom.com"),
    "coinbase": ("coinbase.com",), "binance": ("binance.com",),
    "slack": ("slack.com",), "x": ("x.com", "twitter.com"),
}
_BRAND_CLAIM_RE = re.compile(
    r"\b(?:we are|we're|this is|i am with|writing from|contacting you from|on behalf of|"
    r"member of|representing|your assigned)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:reply|respond|call|contact|confirm|acknowledge|send|provide|share|update|schedule|"
    r"arrange|return|submit|review|open|view|verify)\b.{0,130}\b(?:case|reference|number|time|availability|"
    r"appointment|notice|request|record|details?|information|document|order|delivery|account|"
    r"support|license|envelope|folder|transaction|workspace|subscription)\b"
    r"|\b(?:please|kindly)\b.{0,100}\b(?:reply|respond|call|contact|confirm|acknowledge|send|"
    r"provide|schedule|review|verify)\b",
    re.I | re.S,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:brand impersonation|brand-name impersonation|corporate brand spoofing|"
    r"fake brand email|trademark impersonation|service-brand deception)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|verified official domain|authenticated brand account|"
    r"official support portal|no action (?:is )?requested|brand-impersonation awareness)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:brand impersonation|brand-name spoofing|corporate brand impersonation|"
    r"trademark impersonation|service-brand deception)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "brand_impersonation_detected", "brand_spoofing_detected",
        "corporate_brand_impersonation_detected", "trademark_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("brand_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner brand-impersonation evidence: {value[:120]}"
    return ""


def _brand_risk(email_data: Mapping, text: str) -> tuple[bool, str]:
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    domain = sender_address.rpartition("@")[2].casefold()
    haystack = f"{_canonical_text(sender_name)} {text}".casefold()
    for brand, official_domains in _BRAND_DOMAINS.items():
        if not re.search(rf"\b{re.escape(brand)}\b", haystack):
            continue
        aligned = any(domain == official or domain.endswith("." + official) for official in official_domains)
        if domain and not aligned:
            return True, f"message claims {brand} while using unrelated sender domain {domain}"
    return False, ""


def _behavior_reason(email_data: Mapping, value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes protected-brand impersonation"
    risky, identity_reason = _brand_risk(email_data, text)
    brand_claim = bool(_BRAND_CLAIM_RE.search(text))
    display_name = parseaddr(str(email_data.get("from") or ""))[0]
    display_has_brand = any(re.search(rf"\b{re.escape(brand)}\b", display_name, re.I) for brand in _BRAND_DOMAINS)
    if risky and _ACTION_RE.search(text) and (brand_claim or display_has_brand):
        return identity_reason
    return ""


def evaluate_brand_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type4-brand",
        points=100,
        reason=f"Brand impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="brand-impersonation-type4",
    )]
