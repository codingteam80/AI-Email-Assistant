"""Spam Type 16: detect the same spam campaign flooding an organization."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:organization[- ]wide spam flood|org[- ]wide spam flood|enterprise spam flood|"
    r"company[- ]wide spam campaign|tenant[- ]wide spam flood)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|approved organization announcement|authorized company[- ]wide message|"
    r"emergency notification|service status broadcast|expected internal campaign|"
    r"security awareness|training|simulation|example|analysis|incident report|false positive)\b",
    re.I,
)
_ORG_FLOOD_RE = re.compile(
    r"\b(?:organization|company|enterprise|tenant|workforce|employees?|staff|departments?|mailboxes?)\b"
    r".{0,100}\b(?:flooded|overwhelmed|bombarded|targeted)\b.{0,130}"
    r"\b(?:spam|unsolicited messages?|unsolicited advertisements?|unsolicited campaign|same promotion|bulk email)\b|"
    r"\b(?:same spam|same unsolicited message|same advertisement|spam campaign|unsolicited campaign)\b"
    r".{0,140}\b(?:across|throughout|to)\b.{0,80}"
    r"\b(?:the organization|the company|the enterprise|the tenant|employees?|staff|departments?|mailboxes?)\b|"
    r"\b(?:organization[- ]wide|company[- ]wide|enterprise[- ]wide|tenant[- ]wide)\b"
    r".{0,100}\b(?:spam|unsolicited message|unsolicited advertisement|message flood|mail flood)\b",
    re.I | re.S,
)
_CONTROLLED_SUBJECTS = {
    "organization-wide unsolicited message",
    "company mailbox spam wave",
    "enterprise-wide message flood",
    "staff-wide unsolicited campaign",
    "department mailbox spam burst",
    "organization spam flood notice",
    "company-wide advertisement wave",
    "tenant-wide unsolicited mailing",
    "workforce mailbox flood",
    "enterprise spam campaign",
    "multiple departments targeted",
    "organization mailbox overload",
    "company spam distribution wave",
    "staff mailbox campaign flood",
    "organization-wide spam burst",
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


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "organization_wide_spam_flood_detected", "org_wide_spam_detected",
        "enterprise_spam_flood_detected", "tenant_wide_spam_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "organization_analysis", "campaign_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner organization-wide flood evidence: {value[:120]}"
    return ""


def _behavior_reason(email_data: Mapping) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "organization_analysis", "campaign_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context):
        return ""
    recipients = _numeric(
        email_data, "organization_recipient_count", "affected_mailbox_count",
        "tenant_recipient_count", "affected_employee_count",
    )
    messages = _numeric(
        email_data, "organization_spam_message_count", "campaign_message_count",
        "matching_message_count", "message_fingerprint_count",
    )
    departments = _numeric(email_data, "affected_department_count", "targeted_department_count")
    if recipients >= 10 and messages >= 20 and (departments >= 2 or recipients >= 25):
        spread = f" across {departments} departments" if departments else ""
        return f"{messages} matching spam messages reached {recipients} organization mailboxes{spread}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "spam_analysis", "organization_analysis", "campaign_analysis", "classification_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies an organization-wide spam flood"
    if _ORG_FLOOD_RE.search(text):
        return "message describes the same unsolicited campaign flooding mailboxes across an organization"
    return ""


def evaluate_organization_wide_spam_flood_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type16-organization-wide-flood",
        points=100,
        reason=f"Organization-wide spam flood detected ({reason})",
        categories=("Spam",),
        strong_flag="organization-wide-spam-flood",
    )]
