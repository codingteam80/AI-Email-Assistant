"""Spam Type 5: detect mail sent through an unconsented bulk recipient list."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:bulk-list spam|unauthorized bulk mailing|unconsented mailing list|mass-recipient spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|subscribed|opted in|consented|requested updates|authorized mailing list|"
    r"employee distribution list|internal distribution|association member|current member|"
    r"transactional notice|service announcement|sender allowlisted|trusted sender|false positive|"
    r"security awareness|training|simulation|example|analysis)\b",
    re.I,
)
_CONTENT_CLEAN_RE = re.compile(
    r"\b(?:not spam|not (?:a )?(?:bulk distribution|mass mailing|bulk mailing) list|"
    r"subscribed|opted in|consented|requested updates|authorized mailing list|"
    r"employee distribution list|internal distribution|association member|current member|"
    r"transactional notice|service announcement|sender allowlisted|trusted sender|false positive|"
    r"security awareness|training|simulation)\b",
    re.I,
)
_BULK_LIST_RE = re.compile(
    r"\b(?:full contact list|entire contact list|bulk contact database|large recipient list|"
    r"mass mailing list|bulk distribution list|all addresses in our database|"
    r"thousands of addresses|every address in our records|complete prospect list|"
    r"company-wide prospect database|batch of collected contacts|broad recipient list|"
    r"mailing list (?:was )?assembled from business contacts|broadcast list of contacts)\b",
    re.I,
)
_UNCONSENTED_RE = re.compile(
    r"\b(?:you were added|we added (?:your|this) (?:email |mail )?address|without (?:a )?(?:subscription|signup|request|consent)|"
    r"even if you did not subscribe|no prior signup (?:is |was )?required|selected automatically|"
    r"included automatically|whether or not you requested|without confirming your interest|"
    r"no opt-in (?:is |was )?needed|not based on a subscription)\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "contact-list bulletin",
    "broad recipient update",
    "mass mailing announcement",
    "large-scale address notice",
    "prospect list bulletin",
    "company prospect broadcast",
    "broad list information",
    "assembled mailing-list note",
    "contact broadcast message",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _numeric(email_data: Mapping, *keys: str) -> int:
    for key in keys:
        value = email_data.get(key)
        if value in (None, ""):
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "bulk_list_spam_detected", "unauthorized_bulk_list_detected",
        "large_recipient_list_spam_detected", "unconsented_mailing_list_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner bulk-list evidence: {value[:120]}"
    recipient_count = _numeric(email_data, "recipient_count", "bulk_recipient_count", "estimated_recipient_count")
    unconsented = _true(email_data.get("bulk_list_unconsented")) or str(email_data.get("consent_status") or "").casefold() in {
        "unconsented", "no consent", "not opted in",
    }
    if recipient_count >= 20 and unconsented:
        return f"provider reports {recipient_count} recipients without consent"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CONTENT_CLEAN_RE.search(text):
        return ""
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS:
        return "reported bulk-list subject recognized before full body synchronization"
    if _BULK_LIST_RE.search(text) and _UNCONSENTED_RE.search(text):
        return "message declares mass-list distribution without recipient consent"
    return ""


def evaluate_bulk_list_spam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type5-bulk-list",
        points=100,
        reason=f"Bulk-list spam detected ({reason})",
        categories=("Spam",),
        strong_flag="bulk-list-spam",
    )]
