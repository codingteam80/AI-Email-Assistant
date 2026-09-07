"""Scam/Fraud Type 12: detect business email compromise (BEC)."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_BUSINESS_ROLE_RE = re.compile(
    r"\b(?:ceo|chief executive|cfo|chief financial officer|president|vice president|vp|director|"
    r"executive|company owner|business owner|boss|manager|board chair|finance director|controller|"
    r"accountant|accounts payable|payroll (?:director|manager|team)|hr (?:director|manager)|"
    r"executive assistant|vendor|supplier|contractor|client|customer|attorney|lawyer|escrow officer)\b",
    re.I,
)
_BUSINESS_ACTION_RE = re.compile(
    r"\b(?:send\w*|wir(?:e|es|ed|ing)|transfer\w*|pay|pays|paid|paying|remit\w*|release\w*|"
    r"process\w*|authoriz\w*|approv\w*|buy|buys|buying|bought|purchas\w*|obtain\w*|"
    r"chang\w*|updat\w*|replac\w*|redirect\w*|rerout\w*|shar\w*|email\w*|forward\w*|"
    r"provid\w*|request\w*|ask\w*|need\w*)\b.{0,150}"
    r"\b(?:funds?|money|payment|wire|ach|invoice|balance|beneficiary|bank account|personal account|"
    r"direct[- ]deposit|bank details?|"
    r"gift[- ]cards?|prepaid cards?|card codes?|w-?2s?|tax (?:forms?|records?|documents?)|"
    r"payroll (?:file|records?|data)|employee (?:records?|data|salary|bank details?))\b",
    re.I | re.S,
)
_PAYMENT_CHANGE_RE = re.compile(
    r"\b(?:new|updated|revised|changed|replacement|alternate|different|personal|third[- ]party)\b"
    r".{0,80}\b(?:bank account|account|account details?|bank details?|beneficiary|wire instructions?|"
    r"payment instructions?|routing details?)\b"
    r"|\b(?:disregard|ignore|do not use|don't use)\b.{0,80}\b(?:old|previous|original)\b"
    r".{0,50}\b(?:account|details?|instructions?)\b"
    r"|\b(?:bank account|banking details?|bank details?|beneficiary)\b.{0,35}"
    r"\b(?:changed|updated|revised|replaced|is different)\b",
    re.I | re.S,
)
_SENSITIVE_BUSINESS_RE = re.compile(
    r"\b(?:w-?2s?|tax (?:forms?|records?|documents?)|payroll (?:file|records?|data)|"
    r"employee (?:records?|data|salary list|bank details?)|salary list|direct[- ]deposit (?:file|details?))\b",
    re.I,
)
_PRESSURE_RE = re.compile(
    r"\b(?:urgent|urgently|immediately|right now|today|asap|as soon as possible|confidentially|before (?:cutoff|close of business|closing|"
    r"the meeting ends)|confidential|strictly confidential|keep (?:this|it) secret|between us|"
    r"do not call|don't call|do not verify|don't verify|no need to verify|without verification|"
    r"unavailable by phone|cannot talk|can't talk|in a meeting|traveling|do not discuss|"
    r"bypass (?:the )?(?:portal|approval|normal process))\b",
    re.I,
)
_PERSONAL_CHANNEL_RE = re.compile(
    r"\b(?:personal (?:email|address|account)|alternate email|new email address|reply only to|"
    r"outside (?:the )?(?:company|corporate|vendor) (?:email|portal)|private mailbox)\b",
    re.I,
)
_GIFT_CARD_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid cards?|card codes?|voucher codes?)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:business email compromise|bec scam|bec fraud|ceo fraud|ceo scam|executive impersonation fraud|"
    r"vendor email compromise|supplier email compromise|w-?2 bec scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|verified vendor portal|dual approval completed|"
    r"confirmed (?:by|through) (?:a )?(?:known|trusted|verified) (?:phone|number|channel|contact)|"
    r"confirmed in person|no payment (?:is )?requested|no sensitive (?:data|records?) (?:is|are) requested|"
    r"unchanged bank details|approved corporate process)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:business email compromise|bec fraud|ceo fraud|executive impersonation fraud|"
    r"vendor email compromise|supplier mailbox compromise|w-?2 bec)\b",
    re.I,
)
_FREE_MAIL_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "icloud.com",
    "proton.me", "protonmail.com", "mail.com",
}


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "business_email_compromise_detected", "bec_detected", "ceo_fraud_detected",
        "executive_impersonation_fraud_detected", "vendor_email_compromise_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("bec_analysis", "impersonation_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner business-email-compromise evidence: {value[:120]}"
    return ""


def _sender_risk(email_data: Mapping) -> bool:
    sender_name, sender_address = parseaddr(str(email_data.get("from") or ""))
    reply_address = parseaddr(str(email_data.get("reply_to") or email_data.get("replyTo") or ""))[1]
    sender_domain = sender_address.rpartition("@")[2].casefold()
    reply_domain = reply_address.rpartition("@")[2].casefold()
    evidence = " ".join(str(email_data.get(key) or "") for key in (
        "spam_evidence", "authentication_results", "security_analysis",
    )).casefold()
    role_name = bool(_BUSINESS_ROLE_RE.search(sender_name))
    free_mail_role = role_name and sender_domain in _FREE_MAIL_DOMAINS
    reply_mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    auth_or_lookalike = bool(re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|lookalike|typosquat|spoof", evidence))
    return free_mail_role or reply_mismatch or auth_or_lookalike


def _behavior_reason(email_data: Mapping, value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes business email compromise"
    role = bool(_BUSINESS_ROLE_RE.search(text))
    action = bool(_BUSINESS_ACTION_RE.search(text))
    changed_payment = bool(_PAYMENT_CHANGE_RE.search(text))
    sensitive_business = bool(_SENSITIVE_BUSINESS_RE.search(text))
    pressure = bool(_PRESSURE_RE.search(text))
    personal_channel = bool(_PERSONAL_CHANNEL_RE.search(text))
    gift_card = bool(_GIFT_CARD_RE.search(text))
    sender_risk = _sender_risk(email_data)
    if role and action and pressure and (changed_payment or sensitive_business or personal_channel or gift_card):
        return "an alleged business authority demands a pressured payment or sensitive-data action"
    if role and action and changed_payment and pressure:
        return "an executive, vendor, or adviser redirects a business payment under pressure"
    if role and action and sensitive_business and (pressure or personal_channel or sender_risk):
        return "an alleged business authority requests payroll or tax records through a risky channel"
    if sender_risk and action and pressure and (changed_payment or sensitive_business):
        return "sender-identity risk accompanies a pressured business payment or records request"
    return ""


def evaluate_business_email_compromise_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(email_data, str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type12-business-email-compromise",
        points=100,
        reason=f"Business email compromise detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="business-email-compromise",
    )]
