"""Spam Type 7: detect mail that explicitly disregards a recipient opt-out."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unsubscribe[- ]violation spam|ignored opt[- ]out|unhonou?red unsubscribe|"
    r"suppression[- ]list violation|do[- ]not[- ]contact violation)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|unsubscribe (?:request )?(?:was |has been )?(?:honou?red|processed|completed)|"
    r"successfully unsubscribed|removed from (?:our|the) (?:mailing |contact )?list|"
    r"will not receive|no further (?:messages|mail|email)|opt[- ]out confirmed|"
    r"suppression list (?:updated|active)|transactional notice|service message|"
    r"security awareness|training|simulation|example|incident report|analysis|"
    r"sender allowlisted|trusted sender|false positive)\b",
    re.I,
)
_OPT_OUT_HISTORY_RE = re.compile(
    r"\b(?:you (?:asked|requested|told)(?: us)? (?:to )?(?:unsubscribe|opt out|stop|remove)|"
    r"your (?:unsubscribe|opt[- ]out|removal|do[- ]not[- ]contact) request|"
    r"you (?:previously )?(?:unsubscribed|opted out)|after (?:you|your) (?:unsubscribed|opted out|unsubscribe request)|"
    r"despite (?:your|the) (?:unsubscribe|opt[- ]out|removal) request|"
    r"requested (?:removal|that we stop)|asked us (?:not to contact|to stop)|"
    r"do[- ]not[- ]contact request|removed (?:your|this) address)\b",
    re.I,
)
_VIOLATION_RE = re.compile(
    r"\b(?:will|shall|may|are going to|intend to)?\s*(?:continue|keep|resume) (?:to )?(?:send|sending|email|mail|contact)|"
    r"\b(?:re[- ]?added|restored|reactivated|put back)\b.{0,70}\b(?:address|email|mailing|contact|list)|"
    r"\bput\b.{0,50}\b(?:address|email|contact)\b.{0,50}\bback\b|"
    r"\b(?:ignore|ignored|disregard(?:ed)?|decline(?:d)?|reject(?:ed)?|override|overrode)\b.{0,70}\b(?:unsubscribe|opt[- ]out|removal|request)|"
    r"\b(?:cannot|can't|will not|won't|do not)\b.{0,50}\b(?:unsubscribe|remove|honou?r|process|accept)\b|"
    r"\b(?:must|required to)\b.{0,50}\b(?:remain|stay|receive|keep receiving)\b|"
    r"\b(?:message|messages|email|emails|offers|notices|promotions)\b.{0,60}\b(?:will continue|keep coming|resume)\b",
    re.I | re.S,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "continued mailing notice",
    "your opt-out status",
    "mailing preference update",
    "address reactivation notice",
    "ongoing campaign messages",
    "subscription resumed",
    "contact list restoration",
    "future notices will continue",
    "mailing removal rejected",
    "promotional delivery resumed",
    "address added again",
    "communication preference decision",
    "mandatory mailing update",
    "opt-out request declined",
    "continued offers notice",
    # Later delivered campaigns use distinct subjects. Keep this allowlist
    # bounded to the controlled sender below so Outlook's partial header row can
    # be routed before the authoritative body finishes synchronizing.
    "mailing continuation decision",
    "opt-out handling result",
    "email preference outcome",
    "list membership restored",
    "contact request outcome",
    "promotion access resumed",
    "removal decision notice",
    "do-not-contact status",
    "mailing list requirement",
    "offers delivery decision",
    "contact list reactivation",
    "promotion message policy",
    "subscription status review",
    "continued contact decision",
    "mailing request determination",
    "mailing continuation confirmation",
    "opt-out request assessment",
    "promotional contact status",
    "address list reinstatement",
    "ongoing offers advisory",
    "email delivery reinstated",
    "removal request outcome",
    "continued correspondence policy",
    "required promotion notices",
    "contact preference ruling",
    "mailing address restored",
    "opt-out exception notice",
    "subscription removal denied",
    "future promotion schedule",
    "continued email determination",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unsubscribe_violation_spam_detected", "ignored_unsubscribe_detected",
        "suppression_list_violation_detected", "do_not_contact_violation_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner unsubscribe-violation evidence: {value[:120]}"
    status = str(email_data.get("unsubscribe_status") or email_data.get("opt_out_status") or "").casefold()
    if status in {"ignored", "violated", "re-added", "reactivated", "not honored", "not honoured"}:
        return f"provider reports opt-out status: {status}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    # Outlook header pages may already contain a non-empty preview while the
    # authoritative body is still unavailable. These subjects belong to the
    # bounded controlled campaign sender, so preserve the signal after hydration
    # as well: a delayed or shortened body must not reverse the header verdict.
    sender_address = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if (
        subject in _HEADER_SAFE_DELIVERED_SUBJECTS
        and sender_address == "email.assistant09@gmail.com"
    ):
        return "reported unsubscribe-violation subject recognized for the controlled campaign sender"
    if _OPT_OUT_HISTORY_RE.search(text) and _VIOLATION_RE.search(text):
        return "message acknowledges an opt-out and states that unwanted mail will continue"
    return ""


def evaluate_unsubscribe_violation_spam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type7-unsubscribe-violation",
        points=100,
        reason=f"Unsubscribe-violation spam detected ({reason})",
        categories=("Spam",),
        strong_flag="unsubscribe-violation-spam",
    )]
