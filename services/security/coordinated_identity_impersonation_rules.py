"""Impersonation Type 16: detect an identity cluster with campaign correlation evidence."""
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
_CAMPAIGN_RE = re.compile(
    r"\b(?:shared (?:sending )?infrastructure|shared reply-to|same impersonation campaign|"
    r"coordinated (?:sender )?personas|clustered impersonation campaign|linked identity cluster|"
    r"common campaign operator|shared campaign fingerprint)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|training|simulation|example|research|analysis|incident review|"
    r"coordinated-impersonation warning|false positive|independent senders|legitimate distribution list|"
    r"approved shared service|campaign correlation cleared|no action (?:is )?requested|no request)\b",
    re.I,
)


def _text(value: object) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _address(value: object) -> str:
    return parseaddr(_text(value))[1].casefold().strip()


def _identities(email_data: Mapping) -> set[str]:
    value = (
        email_data.get("related_sender_identities") or email_data.get("campaign_sender_identities")
        or email_data.get("identity_cluster") or []
    )
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return set()
    identities = set()
    for entry in value:
        if isinstance(entry, Mapping):
            raw = entry.get("email") or entry.get("address") or entry.get("identity") or ""
        else:
            raw = entry
        normalized = _address(raw) or _text(raw).casefold()
        if normalized:
            identities.add(normalized)
    return identities


def _correlation_present(email_data: Mapping) -> bool:
    if any(_text(email_data.get(key)) for key in ("campaign_correlation_id", "identity_cluster_id")):
        return True
    value = email_data.get("shared_infrastructure_detected")
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _campaign_reason(email_data: Mapping) -> str:
    for key in (
        "coordinated_identity_evidence", "campaign_analysis", "identity_cluster_analysis",
        "security_analysis",
    ):
        value = _text(email_data.get(key))
        if value and not _CLEAN_CONTEXT_RE.search(value) and _CAMPAIGN_RE.search(value):
            return value[:120]
    return ""


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "coordinated_identity_impersonation_detected", "identity_cluster_impersonation_detected",
        "coordinated_sender_campaign_detected", "multi_identity_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    return ""


def _behavior_reason(email_data: Mapping, body: str) -> str:
    body = _text(body)
    if _CLEAN_CONTEXT_RE.search(body) or not _ACTION_RE.search(body):
        return ""
    identities = _identities(email_data)
    actual_address = _address(email_data.get("from"))
    reason = _campaign_reason(email_data)
    if (
        len(identities) >= 2
        and actual_address in identities
        and _correlation_present(email_data)
        and reason
    ):
        return f"current sender is part of a correlated impersonation identity cluster ({reason})"
    return ""


def evaluate_coordinated_identity_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type16-coordinated-identity",
        points=100,
        reason=f"Coordinated identity impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="coordinated-identity-impersonation",
    )]
