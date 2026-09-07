"""Impersonation Type 7: detect a lookalike of a trusted sender domain."""
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
    r"lookalike-domain warning|typosquat warning|reported as impersonation|"
    r"confirmed alternate domain|verified new domain|approved subsidiary domain|"
    r"no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:lookalike-domain impersonation|lookalike sender domain|typosquatted sender domain|"
    r"domain impersonation)\b",
    re.I,
)
_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _domain(value: object) -> str:
    value = _text(value).casefold().strip().strip(".")
    if "@" in value:
        value = value.rpartition("@")[2]
    return value


def _base_label(domain: str) -> str:
    return domain.split(".", 1)[0]


def _skeleton(label: str) -> str:
    value = label.translate(_SUBSTITUTIONS).replace("rn", "m").replace("vv", "w")
    return re.sub(r"[-_]", "", value)


def _distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    if len(left) == len(right):
        mismatches = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
        if len(mismatches) <= 1:
            return True
        return (
            len(mismatches) == 2
            and mismatches[1] == mismatches[0] + 1
            and left[mismatches[0]] == right[mismatches[1]]
            and left[mismatches[1]] == right[mismatches[0]]
        )
    index = misses = 0
    for char in right:
        if index < len(left) and left[index] == char:
            index += 1
        else:
            misses += 1
            if misses > 1:
                return False
    return True


def _same_or_subdomain(actual: str, expected: str) -> bool:
    return actual == expected or actual.endswith("." + expected)


def _directory_domain(email_data: Mapping, sender_name: str) -> str:
    normalized_name = re.sub(r"[^\w]+", " ", _text(sender_name).casefold()).strip()
    for key in ("known_contacts", "trusted_contacts", "directory_contacts", "contact_directory"):
        value = email_data.get(key)
        if isinstance(value, Mapping):
            for name, address in value.items():
                if re.sub(r"[^\w]+", " ", str(name).casefold()).strip() == normalized_name:
                    return _domain(_address(address))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                if isinstance(item, Mapping):
                    name = item.get("name") or item.get("display_name") or ""
                    if re.sub(r"[^\w]+", " ", str(name).casefold()).strip() == normalized_name:
                        return _domain(_address(item.get("email") or item.get("address") or ""))
    return ""


def _expected_domain(email_data: Mapping, sender_name: str) -> str:
    direct = _domain(
        email_data.get("expected_sender_domain") or email_data.get("known_sender_domain")
        or email_data.get("trusted_sender_domain") or ""
    )
    if direct:
        return direct
    address = _address(
        email_data.get("expected_sender_address") or email_data.get("known_sender_address")
        or email_data.get("trusted_sender_address") or ""
    )
    return _domain(address) or _directory_domain(email_data, sender_name)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "lookalike_domain_detected", "domain_impersonation_detected",
        "typosquatted_sender_domain_detected", "sender_domain_lookalike_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("domain_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner lookalike-domain evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    actual = _domain(sender_address)
    expected = _expected_domain(email_data, sender_name)
    if not actual or not expected or _same_or_subdomain(actual, expected):
        return ""
    actual_label, expected_label = _base_label(actual), _base_label(expected)
    if not actual_label.isascii() or not expected_label.isascii():
        return ""
    actual_skeleton, expected_skeleton = _skeleton(actual_label), _skeleton(expected_label)
    if min(len(actual_skeleton), len(expected_skeleton)) < 5:
        return ""
    if actual_skeleton == expected_skeleton or _distance_at_most_one(actual_skeleton, expected_skeleton):
        return f"sender domain {actual} resembles trusted domain {expected}"
    return ""


def evaluate_lookalike_domain_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type7-lookalike-domain",
        points=100,
        reason=f"Lookalike-domain impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="lookalike-domain-impersonation",
    )]
