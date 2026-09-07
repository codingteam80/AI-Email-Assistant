"""Impersonation Type 6: detect lookalikes of a known sender's email local part."""
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
    r"lookalike warning|reported as impersonation|confirmed alternate (?:email|address)|"
    r"verified (?:new|alternate) (?:email|address)|approved email alias|"
    r"no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:username lookalike|local-part lookalike|sender local-part mismatch|"
    r"known-username impersonation)\b",
    re.I,
)
_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _canonical_text(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _address(value: object) -> str:
    return parseaddr(_canonical_text(value))[1].casefold().strip()


def _parts(address: str) -> tuple[str, str]:
    local, separator, domain = address.casefold().partition("@")
    return (local, domain) if separator else (local, "")


def _skeleton(local: str) -> str:
    value = local.split("+", 1)[0].translate(_SUBSTITUTIONS)
    value = value.replace("rn", "m").replace("vv", "w")
    return re.sub(r"[._-]", "", value)


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) <= 1
    index = mismatches = 0
    for char in right:
        if index < len(left) and left[index] == char:
            index += 1
        else:
            mismatches += 1
            if mismatches > 1:
                return False
    return True


def _directory_expected(email_data: Mapping, sender_name: str) -> str:
    normalized_name = re.sub(r"[^\w]+", " ", _canonical_text(sender_name).casefold()).strip()
    for key in ("known_contacts", "trusted_contacts", "directory_contacts", "contact_directory"):
        value = email_data.get(key)
        if isinstance(value, Mapping):
            for name, address in value.items():
                if re.sub(r"[^\w]+", " ", str(name).casefold()).strip() == normalized_name:
                    return _address(address)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                if isinstance(item, Mapping):
                    name = item.get("name") or item.get("display_name") or ""
                    if re.sub(r"[^\w]+", " ", str(name).casefold()).strip() == normalized_name:
                        return _address(item.get("email") or item.get("address") or "")
    return ""


def _expected_address(email_data: Mapping, sender_name: str) -> str:
    direct = _address(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address")
        or email_data.get("trusted_sender_address") or ""
    )
    if direct:
        return direct
    username = _canonical_text(email_data.get("expected_username") or email_data.get("known_username"))
    domain = _canonical_text(email_data.get("expected_sender_domain") or email_data.get("known_sender_domain"))
    if username:
        return f"{username}@{domain}" if domain else username
    return _directory_expected(email_data, sender_name)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "username_lookalike_detected", "local_part_lookalike_detected",
        "sender_localpart_mismatch_detected", "known_username_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("username_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _canonical_text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner username evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, text: str) -> str:
    text = _canonical_text(text)
    if _CLEAN_CONTEXT_RE.search(text) or not _ACTION_RE.search(text):
        return ""
    sender_name, actual = parseaddr(str(email_data.get("from") or ""))
    actual = actual.casefold().strip()
    expected = _expected_address(email_data, sender_name)
    actual_local, actual_domain = _parts(actual)
    expected_local, expected_domain = _parts(expected)
    if not actual_local or not expected_local or actual == expected or actual_local == expected_local:
        return ""
    # Normal plus-addressing on the expected domain is an alias, not a lookalike.
    if actual_domain and actual_domain == expected_domain and actual_local.split("+", 1)[0] == expected_local:
        return ""
    actual_skeleton, expected_skeleton = _skeleton(actual_local), _skeleton(expected_local)
    if min(len(actual_skeleton), len(expected_skeleton)) < 5:
        return ""
    lookalike = actual_skeleton == expected_skeleton or _edit_distance_at_most_one(
        actual_skeleton, expected_skeleton
    )
    if lookalike:
        return f"sender local part {actual_local} resembles trusted local part {expected_local}"
    return ""


def evaluate_username_localpart_lookalike_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type6-username-localpart-lookalike",
        points=100,
        reason=f"Username or local-part lookalike detected ({reason})",
        categories=("Impersonation",),
        strong_flag="username-localpart-lookalike",
    )]
