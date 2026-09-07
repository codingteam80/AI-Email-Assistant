"""Impersonation Type 15: detect a known participant identity replaced inside a thread."""
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
    r"availability|details?|information|document|record|meeting|appointment|number|thread)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"thread-hijacking warning|conversation-hijacking warning|reported as impersonation|"
    r"adding (?:a )?(?:(?:new|approved)\s+){1,2}(?:colleague|participant)|approved thread participant|"
    r"forwarded message|verified participant change|no action (?:is )?requested|no request)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:conversation hijacking|thread hijacking|reply-chain impersonation|"
    r"thread participant identity mismatch)\b",
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


def _thread_context(email_data: Mapping) -> bool:
    subject = _text(email_data.get("subject"))
    linked = any(_text(email_data.get(key)) for key in (
        "canonical_thread_id", "conversation_id", "thread_id", "in_reply_to",
        "references", "reference_ids",
    ))
    try:
        multi_message = int(email_data.get("thread_count") or 0) > 1
    except (TypeError, ValueError):
        multi_message = False
    return bool((linked or multi_message) and (re.match(r"^\s*(?:re|fw|fwd)\s*:", subject, re.I) or linked))


def _directory_identity(email_data: Mapping, sender_name: str) -> tuple[str, str]:
    normalized_sender = _name(sender_name)
    value = email_data.get("thread_participants") or email_data.get("conversation_participants")
    if isinstance(value, Mapping):
        for name, address in value.items():
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
        email_data.get("expected_thread_sender_name") or email_data.get("expected_conversation_sender_name") or ""
    )
    expected_address = _address(
        email_data.get("expected_thread_sender_address") or email_data.get("expected_conversation_sender_address") or ""
    )
    if expected_name and expected_address:
        return expected_name, expected_address
    return _directory_identity(email_data, sender_name)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "conversation_hijack_detected", "thread_hijack_detected",
        "reply_chain_impersonation_detected", "thread_sender_mismatch_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("thread_security_analysis", "conversation_analysis", "impersonation_analysis", "analysis"):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner thread-hijacking evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body) or not _thread_context(email_data):
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
        return f"existing thread participant {expected_name} changed from {expected_address} to {actual_address}"
    return ""


def evaluate_conversation_thread_hijacking_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type15-conversation-thread-hijacking",
        points=100,
        reason=f"Conversation or thread hijacking detected ({reason})",
        categories=("Impersonation",),
        strong_flag="conversation-thread-hijacking",
    )]
