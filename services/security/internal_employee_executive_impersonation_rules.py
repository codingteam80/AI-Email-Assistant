"""Impersonation Type 11: detect a known employee/executive identity from the wrong address."""
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
    r"availability|details?|information|document|record|meeting|appointment|number|agenda)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"employee impersonation warning|executive impersonation warning|reported as impersonation|"
    r"confirmed alternate (?:employee|executive) address|approved personal address|"
    r"verified directory update|no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:internal employee impersonation|executive impersonation|staff identity impersonation|"
    r"internal directory identity mismatch)\b",
    re.I,
)
_HONORIFIC_RE = re.compile(r"^(?:mr|mrs|ms|miss|dr|prof)\.?\s+", re.I)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _name(value: object) -> str:
    value = _HONORIFIC_RE.sub("", _text(value)).casefold()
    return re.sub(r"[^\w]+", " ", value, flags=re.UNICODE).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _directory_identity(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    normalized_sender = _name(sender_name)
    for key in ("internal_directory", "employee_directory", "executive_directory"):
        value = email_data.get(key)
        if isinstance(value, Mapping):
            for name, entry in value.items():
                address = entry.get("email") or entry.get("address") if isinstance(entry, Mapping) else entry
                if _name(name) == normalized_sender and _address(address):
                    return str(name), _address(address)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for entry in value:
                if isinstance(entry, Mapping):
                    name = entry.get("name") or entry.get("display_name") or ""
                    address = entry.get("email") or entry.get("address") or ""
                    if _name(name) == normalized_sender and _address(address):
                        return str(name), _address(address)
    return "", ""


def _expected_identity(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    expected_name = _text(
        email_data.get("expected_internal_name") or email_data.get("expected_sender_name")
        or email_data.get("known_sender_name") or ""
    )
    expected_address = _address(
        email_data.get("expected_internal_address") or email_data.get("expected_sender_address")
        or email_data.get("known_sender_address") or ""
    )
    if expected_name and expected_address:
        return expected_name, expected_address
    return _directory_identity(email_data, sender_name)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "internal_employee_impersonation_detected", "executive_impersonation_detected",
        "staff_identity_impersonation_detected", "internal_directory_mismatch_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("internal_identity_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner internal-identity evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    expected_name, expected_address = _expected_identity(email_data, sender_name)
    actual_address = sender_address.casefold().strip()
    if (
        _name(sender_name)
        and _name(sender_name) == _name(expected_name)
        and actual_address
        and expected_address
        and actual_address != expected_address
    ):
        return f"internal identity {expected_name} uses {actual_address} instead of directory address {expected_address}"
    return ""


def evaluate_internal_employee_executive_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type11-internal-employee-executive",
        points=100,
        reason=f"Internal employee or executive impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="internal-employee-executive-impersonation",
    )]
