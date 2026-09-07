"""Impersonation Type 5: detect a known person's name used from the wrong address."""
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
    r"impersonation warning|reported as impersonation|confirmed alternate (?:email|address)|"
    r"verified (?:new|alternate) (?:email|address)|approved personal address|"
    r"no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:person-name impersonation|known-person impersonation|contact-name mismatch|"
    r"directory identity mismatch)\b",
    re.I,
)
_HONORIFIC_RE = re.compile(r"^(?:mr|mrs|ms|miss|dr|prof)\.?\s+", re.I)


def _canonical_text(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _normal_name(value: object) -> str:
    text = _HONORIFIC_RE.sub("", _canonical_text(value)).casefold()
    return re.sub(r"[^\w]+", " ", text, flags=re.UNICODE).strip()


def _normal_address(value: object) -> str:
    return parseaddr(_canonical_text(value))[1].casefold().strip()


def _directory_entries(email_data: Mapping) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for key in ("known_contacts", "trusted_contacts", "directory_contacts", "contact_directory"):
        value = email_data.get(key)
        if isinstance(value, Mapping):
            entries.extend((str(name), _normal_address(address)) for name, address in value.items())
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                if isinstance(item, Mapping):
                    entries.append((
                        str(item.get("name") or item.get("display_name") or ""),
                        _normal_address(item.get("email") or item.get("address") or ""),
                    ))
                elif isinstance(item, str):
                    name, address = parseaddr(item)
                    entries.append((name, address.casefold()))
    return [(name, address) for name, address in entries if _normal_name(name) and address]


def _expected_identity(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    expected_name = str(email_data.get("expected_sender_name") or email_data.get("known_sender_name") or "")
    expected_address = _normal_address(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address") or ""
    )
    if expected_name and expected_address:
        return expected_name, expected_address
    normalized_sender = _normal_name(sender_name)
    for name, address in _directory_entries(email_data):
        if _normal_name(name) == normalized_sender:
            return name, address
    return "", ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "person_name_impersonation_detected", "known_person_impersonation_detected",
        "contact_name_mismatch_detected", "directory_identity_mismatch_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("person_name_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _canonical_text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner person-name evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, text: str) -> str:
    text = _canonical_text(text)
    if _CLEAN_CONTEXT_RE.search(text) or not _ACTION_RE.search(text):
        return ""
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    expected_name, expected_address = _expected_identity(email_data, sender_name)
    actual_address = sender_address.casefold().strip()
    if (
        _normal_name(sender_name)
        and _normal_name(sender_name) == _normal_name(expected_name)
        and actual_address
        and expected_address
        and actual_address != expected_address
    ):
        return f"known contact {expected_name} is using {actual_address} instead of {expected_address}"
    return ""


def evaluate_person_name_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type5-person-name",
        points=100,
        reason=f"Person-name impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="person-name-impersonation",
    )]
