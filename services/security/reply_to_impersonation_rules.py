"""Impersonation Type 9: detect trusted senders that divert replies elsewhere."""
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
    r"availability|details?|information|document|record|meeting|appointment|number)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"reply-to warning|reported as impersonation|approved reply service|authorized reply mailbox|"
    r"verified ticketing system|confirmed alternate reply address|no action (?:is )?requested|"
    r"no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:reply-to impersonation|forged reply-to|reply-address diversion|"
    r"mismatched reply destination)\b",
    re.I,
)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _domain(address: str) -> str:
    return address.rpartition("@")[2].casefold().strip(".")


def _values(email_data: Mapping, *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        value = email_data.get(key)
        items = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else (value,)
        for item in items:
            normalized = _text(item).casefold().strip().strip(".")
            if normalized:
                values.add(normalized)
    return values


def _trusted_sender(email_data: Mapping, actual_address: str) -> tuple[bool, str]:
    expected_address = _address(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address")
        or email_data.get("trusted_sender_address") or ""
    )
    expected_domain = _text(
        email_data.get("expected_sender_domain") or email_data.get("known_sender_domain")
        or email_data.get("trusted_sender_domain") or ""
    ).casefold().strip(".")
    actual_domain = _domain(actual_address)
    if expected_address:
        return actual_address == expected_address, _domain(expected_address)
    if expected_domain:
        return actual_domain == expected_domain or actual_domain.endswith("." + expected_domain), expected_domain
    return False, ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "reply_to_impersonation_detected", "forged_reply_to_detected",
        "reply_address_diversion_detected", "reply_destination_mismatch_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("reply_to_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner Reply-To evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    actual_address = _address(email_data.get("from"))
    reply_address = _address(email_data.get("reply_to") or email_data.get("replyTo"))
    trusted, trusted_domain = _trusted_sender(email_data, actual_address)
    if not trusted or not reply_address or reply_address == actual_address:
        return ""
    approved_addresses = {_address(value) for value in _values(
        email_data, "approved_reply_to_addresses", "trusted_reply_to_addresses"
    )}
    approved_domains = _values(email_data, "approved_reply_to_domains", "trusted_reply_to_domains")
    reply_domain = _domain(reply_address)
    if reply_address in approved_addresses or reply_domain in approved_domains:
        return ""
    if trusted_domain and (reply_domain == trusted_domain or reply_domain.endswith("." + trusted_domain)):
        return ""
    return f"trusted sender diverts replies to unrelated address {reply_address}"


def evaluate_reply_to_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type9-reply-to",
        points=100,
        reason=f"Reply-to impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="reply-to-impersonation",
    )]
