"""Impersonation Type 3: detect role or department impersonation."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ROLE_RE = re.compile(
    r"\b(?:ceo|cfo|chief executive|finance director|executive office|board office|"
    r"hr (?:director|manager|department|team)|human resources|payroll (?:office|department|team)|"
    r"it (?:administrator|support|department|help desk)|system administrator|security operations|"
    r"security department|legal counsel|legal department|compliance department|"
    r"accounts payable|accounts receivable|finance department|procurement department|"
    r"vendor management|facilities department|benefits department|recruiting department|"
    r"customer service department|billing department|audit department|payment processor)\b",
    re.I,
)
_CLAIM_RE = re.compile(
    r"\b(?:i am|i'm|this is|we are|we're|i represent|we represent|writing on behalf of|"
    r"contacting you from|contacting you on behalf of|speaking for|from the|member of the|"
    r"acting as|your assigned)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:reply|respond|call|contact|confirm|acknowledge|send|provide|share|update|schedule|"
    r"arrange|return|forward|submit|review|open|view|approve|verify)\b.{0,130}\b(?:case|reference|number|"
    r"time|availability|appointment|notice|request|record|details?|information|document|policy|"
    r"device|support|interview|attendance|invoice|purchase order|meeting|orientation|benefits|"
    r"maintenance|audit|vendor|pay period)\b"
    r"|\b(?:please|kindly)\b.{0,100}\b(?:reply|respond|call|contact|confirm|acknowledge|send|"
    r"provide|schedule|review|approve|verify)\b",
    re.I | re.S,
)
_RISKY_CHANNEL_RE = re.compile(
    r"\b(?:temporary (?:email|address|mailbox)|personal (?:email|address|mailbox)|new email address|"
    r"alternate (?:email|address|mailbox)|different email address|private mailbox|"
    r"department mailbox is unavailable|corporate email is unavailable|system is down|"
    r"mailbox issue|using my personal account|away from the office)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:role impersonation|department impersonation|executive-role impersonation|"
    r"fake department email|organizational-role spoofing|departmental identity fraud)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|verified corporate directory|authenticated department mailbox|"
    r"official company domain|no action (?:is )?requested|no reply (?:is )?requested|"
    r"role-verification policy)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:role impersonation|department impersonation|executive-role spoofing|"
    r"organizational-role impersonation|departmental identity fraud)\b",
    re.I,
)
_FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "proton.me", "protonmail.com", "mail.com",
}


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "role_impersonation_detected", "department_impersonation_detected",
        "organizational_role_impersonation_detected", "executive_role_impersonation_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("role_analysis", "department_analysis", "impersonation_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner role/department evidence: {value[:120]}"
    return ""


def _sender_risk(email_data: Mapping) -> bool:
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    reply_address = parseaddr(str(email_data.get("reply_to") or email_data.get("replyTo") or ""))[1]
    sender_domain = sender_address.rpartition("@")[2].casefold()
    reply_domain = reply_address.rpartition("@")[2].casefold()
    evidence = " ".join(str(email_data.get(key) or "") for key in (
        "spam_evidence", "authentication_results", "security_analysis",
    )).casefold()
    free_mail_role = sender_domain in _FREE_MAIL_DOMAINS and bool(_ROLE_RE.search(sender_name))
    reply_mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    auth_or_lookalike = bool(re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|lookalike|typosquat|spoof", evidence))
    return free_mail_role or reply_mismatch or auth_or_lookalike


def _behavior_reason(email_data: Mapping, value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes role or department impersonation"
    role = bool(_ROLE_RE.search(text))
    claim = bool(_CLAIM_RE.search(text))
    action = bool(_ACTION_RE.search(text))
    risky_channel = bool(_RISKY_CHANNEL_RE.search(text))
    sender_risk = _sender_risk(email_data)
    if role and claim and action and (risky_channel or sender_risk):
        return "claimed organizational role or department requests action through an inconsistent sender"
    if role and action and risky_channel and sender_risk:
        return "departmental authority is asserted through an unrelated personal or diverted channel"
    return ""


def evaluate_role_department_impersonation_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="impersonation-type3-role-department",
        points=100,
        reason=f"Role or department impersonation detected ({reason})",
        categories=("Impersonation",),
        strong_flag="role-department-impersonation",
    )]
