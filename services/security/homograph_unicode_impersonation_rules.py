"""Impersonation Type 8: detect Unicode homographs of a trusted identity."""
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
    r"homograph warning|unicode impersonation warning|reported as impersonation|"
    r"verified internationalized domain|approved unicode address|no action (?:is )?requested|"
    r"no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:homograph impersonation|unicode impersonation|unicode confusable|"
    r"mixed-script sender impersonation|internationalized sender spoofing)\b",
    re.I,
)
_CONFUSABLES = str.maketrans({
    "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o",
    "р": "p", "Р": "p", "с": "c", "С": "c", "у": "y", "У": "y",
    "х": "x", "Х": "x", "і": "i", "І": "i", "ј": "j", "Ј": "j",
    "к": "k", "К": "k", "м": "m", "М": "m", "т": "t", "Т": "t",
    "в": "b", "В": "b", "н": "h", "Н": "h", "г": "r", "Г": "r",
    "ԝ": "w", "Ԝ": "w", "α": "a", "Α": "a", "ε": "e", "Ε": "e",
    "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p", "κ": "k", "Κ": "k",
    "τ": "t", "Τ": "t", "χ": "x", "Χ": "x", "ι": "i", "Ι": "i",
})


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _decode_idna(value: str) -> str:
    labels = []
    for label in value.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except (UnicodeError, ValueError):
            labels.append(label)
    return ".".join(labels)


def _skeleton(value: str) -> str:
    value = _decode_idna(_text(value)).translate(_CONFUSABLES).casefold()
    value = unicodedata.normalize("NFKD", value)
    return "".join(char for char in value if not unicodedata.combining(char))


def _domain(value: object) -> str:
    value = _text(value).casefold().strip().strip(".")
    return value.rpartition("@")[2] if "@" in value else value


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


def _has_unicode_signal(value: str) -> bool:
    decoded = _decode_idna(value)
    return value.startswith("xn--") or ".xn--" in value or any(ord(char) > 127 for char in decoded)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "homograph_impersonation_detected", "unicode_impersonation_detected",
        "unicode_confusable_detected", "mixed_script_sender_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("unicode_analysis", "impersonation_analysis", "security_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner Unicode-homograph evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    _, sender_address = parseaddr(str(email_data.get("from") or ""))
    actual = _domain(sender_address)
    expected = _expected_domain(email_data)
    if (
        not actual
        or not expected
        or actual == expected
        or _decode_idna(actual).casefold() == _decode_idna(expected).casefold()
        or not _has_unicode_signal(actual)
    ):
        return ""
    if _skeleton(actual) == _skeleton(expected):
        return f"Unicode sender domain {actual} is visually confusable with trusted domain {expected}"
    return ""


def evaluate_homograph_unicode_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type8-homograph-unicode",
        points=100,
        reason=f"Homograph or Unicode impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="homograph-unicode-impersonation",
    )]
