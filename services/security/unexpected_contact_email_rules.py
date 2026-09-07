"""Suspicious Type 2: identify first-contact email with no expected relationship."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:unexpected[- ]contact email|unexpected sender contact|"
    r"unknown first contact|unfamiliar sender email|unanticipated contact)\b",
    re.I,
)
_UNEXPECTED_CONTACT_RE = re.compile(
    r"\b(?:we have not (?:communicated|corresponded|spoken) before|"
    r"we have no previous (?:conversation|correspondence|contact)|"
    r"this is my first (?:message|email|note) to you|"
    r"contacting you for the first time|first time contacting you|"
    r"you (?:do not|don't) know (?:me|this sender)|"
    r"you may not recognize (?:me|my name|this sender|this address)|"
    r"you were not expecting this (?:message|email|note)|"
    r"this (?:contact|message|email|note) (?:may be|is) unexpected|"
    r"not in your contacts|unknown sender|unfamiliar (?:person|sender|contact)|"
    r"without (?:a |any )?prior (?:introduction|contact|conversation|correspondence)|"
    r"without previous contact|no earlier correspondence|"
    r"found your (?:email )?address in (?:a |the )?(?:public )?(?:directory|listing)|"
    r"out of the blue|new contact)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|"
    r"research|analysis|detection guidance|quoted example|false positive|"
    r"known sender|trusted sender|sender allowlisted|expected contact|"
    r"scheduled introduction|referred by|introduced by (?:a )?mutual contact|existing relationship|"
    r"active conversation|requested contact|contact request you submitted|"
    r"conference follow-up|event registration|support ticket)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "we have not communicated before",
    "this is my first message to you",
    "you may not recognize this sender",
    "reaching you without a prior introduction",
    "we have no previous conversation",
    "this contact may be unexpected",
    "i found your address in a public directory",
    "you were not expecting this message",
    "this sender is not in your contacts",
    "contacting you for the first time",
    "there is no earlier correspondence between us",
    "this message arrives without prior contact",
    "you do not know this sender",
    "an unfamiliar person is reaching out",
    "this note comes from a new contact",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _false(value: object) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)) and value == 0:
        return True
    return isinstance(value, str) and value.casefold().strip() in {"false", "no", "unknown", "unrecognized"}


def _count(email_data: Mapping) -> int | None:
    for key in ("prior_message_count", "sender_message_count", "sender_occurrence_count"):
        value = email_data.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return None


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "unexpected_contact_email_detected",
        "unexpected_sender_contact_detected",
        "unknown_first_contact_detected",
        "unfamiliar_sender_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    first_contact = any(_true(email_data.get(key)) for key in (
        "first_contact", "is_first_contact", "new_sender",
    ))
    sender_unknown = any(_false(email_data.get(key)) for key in (
        "sender_known", "sender_in_contacts", "prior_relationship",
    ))
    count = _count(email_data)
    if first_contact and (sender_unknown or count == 0):
        return "mailbox metadata identifies an unknown first-contact sender"
    for key in (
        "suspicious_classification",
        "contact_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner unexpected-contact evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "contact_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies an unexpected-contact email"
    if _UNEXPECTED_CONTACT_RE.search(text):
        return "sender explicitly states that no prior contact or recognized relationship exists"
    return ""


def evaluate_unexpected_contact_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type2-unexpected-contact",
        points=100,
        reason=f"Unexpected-contact email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="unexpected-contact-email",
    )]
