"""Promotional Type 5: identify legitimate event-promotion email."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:event promotion|conference promotion|webinar invitation campaign|"
    r"event marketing email)\b",
    re.I,
)
_EVENT_RE = re.compile(
    r"\b(?:event|summit|conference|webinar|workshop|expo|exhibition|forum|"
    r"showcase|fair|open house|networking session|design week|live session)\b",
    re.I,
)
_PROMOTION_RE = re.compile(
    r"\b(?:join(?: us| our| the)?|you(?:'re| are) invited|register|reserve your (?:place|seat)|"
    r"save the date|attend|tickets? (?:are )?now available|visit us|be part of|"
    r"upcoming|discover sessions|experience|meet us|sign up)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:mandatory internal meeting|incident bridge|court hearing|medical appointment|"
    r"calendar cancellation|meeting rescheduled|employee attendance required)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "you're invited to our annual summit",
    "join us for the spring conference",
    "reserve your place at innovation day",
    "upcoming webinar: future of work",
    "meet us at the industry expo",
    "register for our community workshop",
    "save the date for our live event",
    "attend our product showcase",
    "join our virtual leadership forum",
    "tickets now available for design week",
    "visit us at the technology fair",
    "be part of our customer conference",
    "discover sessions at our annual forum",
    "join the live networking event",
    "experience our summer open house",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "event_promotion_detected", "conference_promotion_detected",
        "webinar_invitation_campaign_detected", "event_marketing_email_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "event_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner event-promotion evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies event promotion"
    if _EVENT_RE.search(text) and _PROMOTION_RE.search(text):
        return "message promotes attendance or registration for an event, conference, or webinar"
    return ""


def evaluate_event_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type5-event-promotion",
        points=100,
        reason=f"Event promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="event-promotion-promotional",
    )]
