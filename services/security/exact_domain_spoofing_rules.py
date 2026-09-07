"""Impersonation Type 10: detect an exact trusted From domain that fails authentication."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ACTION_RE = re.compile(
    r"\b(?:please|kindly)\b.{0,120}\b(?:reply|respond|call|contact|confirm|acknowledge|"
    r"send|provide|share|review|schedule|arrange|return|submit|update)\b|"
    r"\b(?:reply|respond|call|contact|confirm|acknowledge|send|provide|share|review|"
    r"schedule|arrange|return|submit|update)\b.{0,130}\b(?:request|reference|case|time|"
    r"availability|details?|information|document|record|meeting|appointment|number)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"spoofing warning|reported as impersonation|mailing list|forwarded message|"
    r"authenticated relay|arc[- ]validated|known forwarding service|dmarc (?:aggregate )?report|"
    r"authentication test|no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:exact-domain spoofing|exact domain impersonation|forged header-from domain|"
    r"same-domain spoofing)\b",
    re.I,
)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _domain(value: object) -> str:
    value = _text(value).casefold().strip().strip(".")
    if "@" in value:
        value = value.rpartition("@")[2]
    return value


def _expected_domain(email_data: Mapping) -> str:
    direct = _domain(
        email_data.get("expected_sender_domain") or email_data.get("known_sender_domain")
        or email_data.get("trusted_sender_domain") or ""
    )
    if direct:
        return direct
    address = parseaddr(str(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address")
        or email_data.get("trusted_sender_address") or ""
    ))[1]
    return _domain(address)


def _authentication_failures(email_data: Mapping) -> tuple[bool, str]:
    evidence = " ".join(_text(email_data.get(key)) for key in (
        "spam_evidence", "authentication_results", "security_analysis", "auth_results"
    )).casefold()
    results = {}
    for protocol in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{protocol}\s*[=:]\s*(pass|fail|softfail|neutral|none)\b", evidence)
        direct = _text(email_data.get(f"{protocol}_result")).casefold()
        results[protocol] = direct or (match.group(1) if match else "")
    decisive = results["dmarc"] == "fail" or sum(value in {"fail", "softfail"} for value in results.values()) >= 2
    summary = ", ".join(f"{key}={value}" for key, value in results.items() if value)
    return decisive, summary


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "exact_domain_spoofing_detected", "same_domain_spoofing_detected",
        "forged_header_from_detected", "header_from_domain_spoofed",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("domain_spoofing_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner exact-domain evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    _, sender_address = parseaddr(str(email_data.get("from") or ""))
    actual_domain = _domain(sender_address)
    expected_domain = _expected_domain(email_data)
    decisive_failure, summary = _authentication_failures(email_data)
    if actual_domain and actual_domain == expected_domain and decisive_failure:
        return f"visible From domain {actual_domain} exactly matches trusted domain but authentication failed ({summary})"
    return ""


def evaluate_exact_domain_spoofing_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type10-exact-domain-spoofing",
        points=100,
        reason=f"Exact-domain spoofing detected ({reason})",
        categories=("Impersonation",),
        strong_flag="exact-domain-spoofing",
    )]
