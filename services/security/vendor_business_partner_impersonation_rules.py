"""Impersonation Type 12: detect a known vendor/partner name from an unrelated domain."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ACTION_RE = re.compile(
    r"\b(?:please|kindly)\b.{0,120}\b(?:reply|respond|call|contact|confirm|acknowledge|"
    r"send|provide|share|review|schedule|arrange|return|submit|update)\b|"
    r"\b(?:reply|respond|call|contact|confirm|acknowledge|send|provide|share|review|"
    r"schedule|arrange|return|submit|update)\b.{0,130}\b(?:request|reference|case|time|"
    r"availability|details?|information|document|record|meeting|appointment|number|agreement)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"vendor impersonation warning|partner impersonation warning|reported as impersonation|"
    r"confirmed alternate vendor domain|approved partner mailbox|verified supplier update|"
    r"no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:vendor impersonation|business-partner impersonation|supplier identity impersonation|"
    r"trusted-vendor domain mismatch)\b",
    re.I,
)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _name(value: object) -> str:
    return re.sub(r"[^\w]+", " ", _text(value).casefold(), flags=re.UNICODE).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _domain(value: object) -> str:
    value = _text(value).casefold().strip().strip(".")
    return value.rpartition("@")[2] if "@" in value else value


def _directory_vendor(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    normalized_sender = _name(sender_name)
    for key in ("trusted_vendors", "vendor_directory", "business_partners", "partner_directory"):
        value = email_data.get(key)
        if isinstance(value, Mapping):
            for name, entry in value.items():
                raw = (entry.get("domain") or entry.get("email") or entry.get("address")) if isinstance(entry, Mapping) else entry
                expected_domain = _domain(raw)
                if _name(name) == normalized_sender and expected_domain:
                    return str(name), expected_domain
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for entry in value:
                if isinstance(entry, Mapping):
                    name = entry.get("name") or entry.get("vendor_name") or entry.get("partner_name") or ""
                    raw = entry.get("domain") or entry.get("email") or entry.get("address") or ""
                    if _name(name) == normalized_sender and _domain(raw):
                        return str(name), _domain(raw)
    return "", ""


def _expected_vendor(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    expected_name = _text(
        email_data.get("expected_vendor_name") or email_data.get("expected_partner_name") or ""
    )
    expected_domain = _domain(
        email_data.get("expected_vendor_domain") or email_data.get("expected_partner_domain")
        or email_data.get("expected_vendor_address") or email_data.get("expected_partner_address") or ""
    )
    if expected_name and expected_domain:
        return expected_name, expected_domain
    return _directory_vendor(email_data, sender_name)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "vendor_impersonation_detected", "business_partner_impersonation_detected",
        "supplier_identity_impersonation_detected", "trusted_vendor_mismatch_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("vendor_identity_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner vendor-identity evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    expected_name, expected_domain = _expected_vendor(email_data, sender_name)
    actual_domain = _domain(sender_address)
    if (
        _name(sender_name)
        and _name(sender_name) == _name(expected_name)
        and actual_domain
        and expected_domain
        and actual_domain != expected_domain
        and not actual_domain.endswith("." + expected_domain)
    ):
        return f"trusted vendor {expected_name} uses unrelated sender domain {actual_domain} instead of {expected_domain}"
    return ""


def evaluate_vendor_business_partner_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type12-vendor-business-partner",
        points=100,
        reason=f"Vendor or business-partner impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="vendor-business-partner-impersonation",
    )]
