"""Impersonation Type 14: detect trusted accounts with explicit compromise telemetry."""
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
_COMPROMISE_RE = re.compile(
    r"\b(?:compromised (?:account|mailbox)|account takeover|mailbox takeover|impossible travel|"
    r"anomalous (?:sender|mailbox|account) session|malicious (?:inbox|mailbox) rule|"
    r"stolen (?:session|oauth|access) token|oauth token theft|suspicious mailbox delegation|"
    r"verified credential theft|known compromised sender|session-cookie theft)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"compromised-account warning|false positive|account remains secure|no compromise detected|"
    r"telemetry cleared|incident resolved before delivery|no action (?:is )?requested|no request)\b",
    re.I,
)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _domain(value: object) -> str:
    value = _text(value).casefold().strip().strip(".")
    return value.rpartition("@")[2] if "@" in value else value


def _trusted_alignment(email_data: Mapping, actual_address: str) -> bool:
    expected_address = _address(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address")
        or email_data.get("trusted_sender_address") or ""
    )
    if expected_address:
        return actual_address == expected_address
    expected_domain = _domain(
        email_data.get("expected_sender_domain") or email_data.get("known_sender_domain")
        or email_data.get("trusted_sender_domain") or ""
    )
    return bool(expected_domain and _domain(actual_address) == expected_domain)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "sender_account_compromised", "account_takeover_detected",
        "mailbox_compromise_detected", "known_compromised_sender_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    return ""


def _telemetry_reason(email_data: Mapping) -> str:
    for key in (
        "account_compromise_evidence", "account_compromise_analysis",
        "account_takeover_analysis", "sender_risk_analysis", "security_analysis",
    ):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _COMPROMISE_RE.search(value):
            return f"account-compromise telemetry: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    _, sender_address = parseaddr(str(email_data.get("from") or ""))
    actual_address = sender_address.casefold().strip()
    telemetry = _telemetry_reason(email_data)
    if actual_address and _trusted_alignment(email_data, actual_address) and telemetry:
        return telemetry
    return ""


def evaluate_compromised_account_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type14-compromised-account",
        points=100,
        reason=f"Compromised-account impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="compromised-account-impersonation",
    )]
