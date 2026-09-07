"""Spam Type 13: detect unsolicited commercial content injected into a reply chain."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:reply[- ]chain spam|conversation spam|thread[- ]injection spam|"
    r"reply[- ]thread spam|conversation[- ]injected spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|requested information|requested quote|expected follow[- ]up|"
    r"active project|approved participant|"
    r"security awareness|training|simulation|example|analysis|incident report|false positive)\b",
    re.I,
)
_THREAD_SPAM_RE = re.compile(
    r"\b(?:unsolicited (?:promotion|offer|advertisement|commercial message|sales message)|"
    r"unrelated (?:promotion|offer|advertisement|sales pitch|commercial message)|"
    r"spam (?:promotion|offer|advertisement|message)|commercial advertisement)\b"
    r".{0,180}\b(?:reply chain|reply thread|existing (?:conversation|thread)|active (?:conversation|thread)|"
    r"conversation history|email thread|conversation|thread)\b|"
    r"\b(?:reply chain|reply thread|existing (?:conversation|thread)|active (?:conversation|thread)|"
    r"conversation history|email thread|conversation|thread)\b.{0,180}"
    r"\b(?:unsolicited (?:promotion|offer|advertisement|commercial message|sales message)|"
    r"unrelated (?:promotion|offer|advertisement|sales pitch|commercial message)|"
    r"spam (?:promotion|offer|advertisement|message)|commercial advertisement)\b|"
    r"\b(?:inserted|added|injected)\b.{0,80}\b(?:promotion|advertisement|sales pitch|spam message)\b"
    r".{0,100}\b(?:conversation|thread|reply chain)\b",
    re.I | re.S,
)
_PROMO_RE = re.compile(
    r"\b(?:promotion|advertisement|commercial offer|sales offer|sales pitch|discount|catalog|"
    r"buy now|shop now|order now|special offer)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "re: quarterly planning update",
    "re: project schedule discussion",
    "re: team status conversation",
    "re: requested document thread",
    "re: meeting follow-up notes",
    "re: service review conversation",
    "re: weekly operations update",
    "re: account discussion thread",
    "re: delivery planning conversation",
    "re: budget review follow-up",
    "re: shared workspace update",
    "re: vendor discussion notes",
    "re: support conversation update",
    "re: contract review thread",
    "re: monthly report discussion",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _numeric(email_data: Mapping, *keys: str) -> int:
    for key in keys:
        value = email_data.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _thread_context(email_data: Mapping) -> bool:
    subject = str(email_data.get("subject") or "")
    linked = any(str(email_data.get(key) or "").strip() for key in (
        "conversation_id", "thread_id", "canonical_thread_id", "in_reply_to", "references",
    ))
    return bool(re.match(r"^\s*(?:re|fw|fwd)\s*:", subject, re.I) or linked or _numeric(email_data, "thread_count") > 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "reply_chain_spam_detected", "conversation_spam_detected",
        "thread_injection_spam_detected", "reply_thread_spam_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "conversation_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner reply-chain spam evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "conversation_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text) or not _thread_context(email_data):
        return ""
    unrelated = _true(email_data.get("message_unrelated_to_thread")) or _true(
        email_data.get("thread_topic_mismatch_detected")
    )
    prior_messages = _numeric(email_data, "thread_count", "prior_thread_message_count")
    if unrelated and prior_messages >= 1 and _PROMO_RE.search(text):
        return "commercial content is unrelated to the established conversation topic"
    if _THREAD_SPAM_RE.search(text):
        return "message explicitly injects unsolicited commercial content into a reply chain"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "conversation_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies reply-chain spam"
    if _THREAD_SPAM_RE.search(text):
        return "message explicitly describes unsolicited promotion inside a conversation"
    return ""


def evaluate_reply_chain_conversation_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, text) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type13-reply-chain-conversation",
        points=100,
        reason=f"Reply-chain or conversation spam detected ({reason})",
        categories=("Spam",),
        strong_flag="reply-chain-conversation-spam",
    )]
