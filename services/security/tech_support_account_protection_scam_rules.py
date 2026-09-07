"""Scam/Fraud Type 10: detect tech-support and account-protection scams."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_SUPPORT_RE = re.compile(
    r"\b(?:tech(?:nical)? support|support|support (?:team|desk|agent|technician)|help ?desk|"
    r"computer technician|antivirus support|security (?:support|specialist)|repair technician)\b",
    re.I,
)
_PROTECTION_IDENTITY_RE = re.compile(
    r"\b(?:fraud|security|account protection|loss prevention) (?:department|team|unit|center|centre|"
    r"specialist|agent)|bank protection team|account security center\b",
    re.I,
)
_COMPROMISE_RE = re.compile(
    r"\b(?:infected|virus|malware|hacked|compromised|breached|under attack|exposed|"
    r"unauthorized (?:access|withdrawals?|transactions?)|suspicious withdrawals?|bank account exposed|"
    r"computer (?:is )?locked|device (?:is )?locked|router compromised|security risk|at risk)\b",
    re.I,
)
_REMOTE_ACCESS_RE = re.compile(
    r"\b(?:install|download|run|open|launch|allow|enable|grant|start|starts|starting)\b.{0,100}"
    r"\b(?:remote (?:access|desktop|support|session|tool|software|app)|remote-control (?:tool|software)|"
    r"screen sharing|screen-share|remote cleanup session|anydesk|teamviewer|ultraviewer|supremo|logmein)\b"
    r"|\b(?:remote (?:access|desktop|support|session)|screen sharing)\b.{0,80}"
    r"\b(?:allow|enable|grant|connect|install|start)\b",
    re.I | re.S,
)
_SUPPORT_PAYMENT_RE = re.compile(
    r"\b(?:pay|send|transfer|wire|buy|purchase|provide|require|requires|request|requests|demand|demands)\b.{0,120}"
    r"\b(?:service|repair|cleanup|activation|support|technician|security)?\s*(?:fee|charge|payment|cost|"
    r"gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto|moneygram|western union)\b"
    r"|\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto|moneygram|"
    r"western union)\b.{0,100}\b(?:repair|cleanup|support|technician|activation|protect|secure)\b",
    re.I | re.S,
)
_SAFE_ACCOUNT_RE = re.compile(
    r"\b(?:safe|secure|protected|protection|temporary|holding|safeguard)\s+"
    r"(?:bank )?(?:account|wallet)|account (?:kept|held) in reserve\b",
    re.I,
)
_MOVE_FUNDS_RE = re.compile(
    r"\b(?:move|transfer|wire|send|withdraw|reroute|relocate|shift|deposit)\b.{0,130}"
    r"\b(?:money|funds?|balance|savings|cash|account|bitcoin|cryptocurrency|crypto|wallet)\b"
    r"|\b(?:money|funds?|balance|savings|cash)\b.{0,100}"
    r"\b(?:to|into)\b.{0,45}\b(?:account|wallet|bitcoin|cryptocurrency|crypto)\b",
    re.I | re.S,
)
_UNUSUAL_DEST_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"personal account|holding account|protected account|safe account|secure account|cash deposit|"
    r"bitcoin atm|crypto atm|moneygram|western union)\b",
    re.I,
)
_PRESSURE_RE = re.compile(
    r"\b(?:immediately|right now|urgent|today|within (?:an hour|one hour|24 hours)|asap|"
    r"do not call (?:the )?bank|don't call (?:the )?bank|do not verify|keep (?:this|it) (?:secret|"
    r"confidential)|do not tell anyone|don't tell anyone|remain confidential|no time to verify)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:tech[- ]support scam|technical support scam|remote support scam|account[- ]protection scam|"
    r"safe[- ]account scam|bank protection scam|account safeguarding scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|scheduled support appointment|approved support ticket|"
    r"verified support session|official bank app|review (?:it|the alert) in (?:the )?bank app|"
    r"no transfer (?:is )?requested|no payment (?:is )?requested|never move money to a safe account)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:tech[- ]support scam|technical support fraud|remote support scam|account[- ]protection scam|"
    r"safe[- ]account scam|bank protection scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "tech_support_scam_detected", "account_protection_scam_detected",
        "safe_account_scam_detected", "remote_support_scam_detected",
        "bank_protection_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("tech_support_analysis", "account_protection_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner tech-support/account-protection evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes a tech-support or account-protection scam"
    support = bool(_SUPPORT_RE.search(text))
    protector = bool(_PROTECTION_IDENTITY_RE.search(text))
    compromise = bool(_COMPROMISE_RE.search(text))
    remote_access = bool(_REMOTE_ACCESS_RE.search(text))
    support_payment = bool(_SUPPORT_PAYMENT_RE.search(text))
    safe_account = bool(_SAFE_ACCOUNT_RE.search(text))
    move_funds = bool(_MOVE_FUNDS_RE.search(text))
    unusual = bool(_UNUSUAL_DEST_RE.search(text))
    pressure = bool(_PRESSURE_RE.search(text))
    if support and compromise and remote_access and (support_payment or pressure):
        return "alleged technical support uses a compromise warning to obtain remote access"
    if support and compromise and support_payment and (unusual or pressure):
        return "alleged technical support demands an urgent or irreversible repair payment"
    if safe_account and move_funds and (protector or compromise or pressure):
        return "alleged account protection directs funds into a supposed safe or holding account"
    if protector and compromise and move_funds and unusual and pressure:
        return "alleged security staff direct threatened funds through a risky protection channel"
    return ""


def evaluate_tech_support_account_protection_scam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type10-tech-support-account-protection",
        points=100,
        reason=f"Tech-support or account-protection scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="tech-support-account-protection-scam",
    )]
