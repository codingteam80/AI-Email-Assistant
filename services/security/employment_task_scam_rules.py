"""Scam/Fraud Type 7: detect employment and task scams."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_EMPLOYMENT_RE = re.compile(
    r"\b(?:job|employment|position|vacancy|role|career|recruiter|recruitment|hiring|hire|"
    r"interview|candidate|applicant|employer|work[- ]from[- ]home|remote work|remote job|"
    r"onboarding|salary|payroll|mystery shopper|personal assistant|data entry|reshipping)\b",
    re.I,
)
_TASK_RE = re.compile(
    r"\b(?:paid tasks?|task platform|task group|commission tasks?|merchant tasks?|rating tasks?|"
    r"review tasks?|click tasks?|like tasks?|product boosting|app optimization|order grabbing|"
    r"complete (?:the |your )?tasks?|task batch|daily tasks?|withdraw (?:your )?(?:earnings|commission)|"
    r"unlock (?:the )?(?:next )?tasks?)\b",
    re.I,
)
_APPLICANT_FEE_RE = re.compile(
    r"\b(?:training|onboarding|registration|application|background check|equipment|software|"
    r"security|activation|starter kit|certification) (?:fee|charge|deposit|payment|cost)\b"
    r"|\b(?:pay|send|transfer|buy|purchase)\b.{0,100}\b(?:training materials?|office equipment|"
    r"work equipment|laptop|computer|software license|starter kit|background check)\b",
    re.I | re.S,
)
_PAY_RE = re.compile(
    r"\b(?:pay|pays|paying|paid|send|sends|sending|sent|transfer|transfers|transferring|"
    r"transferred|buy|buys|buying|bought|purchase|purchases|purchasing|purchased|deposit|"
    r"deposits|deposited|top up|top-up|recharge|add funds?)\b",
    re.I,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"western union|moneygram|money transfer|friends and family|personal account)\b",
    re.I,
)
_NO_INTERVIEW_RE = re.compile(
    r"\b(?:no interview|without an interview|hired immediately|immediate hire|instant hire|"
    r"guaranteed (?:job|position|employment)|position guaranteed|job guaranteed)\b",
    re.I,
)
_FAKE_CHECK_RE = re.compile(
    r"\b(?:check|cheque|e-check|electronic check)\b.{0,140}\b(?:deposit|mobile deposit|cash)\b"
    r".{0,180}\b(?:buy|purchase|send|transfer|refund|return)\b.{0,100}"
    r"\b(?:equipment|computer|laptop|software|gift[- ]cards?|excess|remainder|difference|funds?)\b"
    r"|\b(?:deposit|cash)\b.{0,100}\b(?:check|cheque|e-check|electronic check)\b.{0,180}"
    r"\b(?:buy|purchase|send|transfer|refund|return)\b.{0,100}"
    r"\b(?:equipment|computer|laptop|gift[- ]cards?|excess|remainder|difference|funds?)\b",
    re.I | re.S,
)
_TASK_DEPOSIT_RE = re.compile(
    r"\b(?:deposit|top up|top-up|recharge|add funds?|fund the account|pay a negative balance)\b"
    r".{0,140}\b(?:task|batch|order|commission|earnings|withdraw|withdrawal|unlock|continue|complete)\b"
    r"|\b(?:task|batch|order|commission|earnings|withdraw|withdrawal|unlock|continue|complete)\b"
    r".{0,140}\b(?:deposit|top up|top-up|recharge|add funds?|fund the account|negative balance)\b",
    re.I | re.S,
)
_MONEY_MULE_RE = re.compile(
    r"\b(?:receive|accept)\b.{0,80}\b(?:money|funds?|payments?|transfers?)\b.{0,120}"
    r"\b(?:forward|send|transfer|wire)\b.{0,100}\b(?:money|funds?|payments?|portion|remainder)\b"
    r"|\b(?:(?:use|requires?|provide) (?:your )?personal (?:bank )?account|"
    r"route payments? through your account)\b"
    r".{0,140}\b(?:forward|send|transfer|keep (?:a |the )?commission)\b",
    re.I | re.S,
)
_RESHIPPING_RE = re.compile(
    r"\b(?:receive|accept)\b.{0,100}\b(?:packages?|parcels?|shipments?)\b.{0,120}"
    r"\b(?:reship|re-ship|forward|repackage|mail)\b"
    r"|\b(?:package inspector|shipping coordinator|reshipping agent)\b",
    re.I | re.S,
)
_PERSONAL_CHANNEL_RE = re.compile(r"\b(?:telegram|whatsapp|signal|private chat|personal messaging account)\b", re.I)
_EARNINGS_LURE_RE = re.compile(
    r"\b(?:guaranteed earnings?|guaranteed salary|high commission|instant commission|daily profit|"
    r"earn \$?\d+ (?:per day|daily)|easy money|quick earnings?)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:fake job|job scam|employment scam|recruitment scam|task scam|paid-task scam|"
    r"work-from-home scam|reshipping scam|money mule job)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training simulation|example scam|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|fraud prevention|employer (?:will |shall )?(?:pay|cover|provide)|"
    r"company-provided equipment|no fee (?:is )?required|no payment (?:is )?required|"
    r"official applicant portal|verified payroll portal)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake job|job scam|employment scam|recruitment scam|task scam|reshipping scam|"
    r"money mule job|fake-check employment scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "employment_scam_detected", "job_scam_detected", "task_scam_detected",
        "recruitment_scam_detected", "reshipping_scam_detected", "money_mule_job_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("employment_analysis", "job_analysis", "task_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner employment/task-scam evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes an employment or paid-task scam"
    employment = bool(_EMPLOYMENT_RE.search(text))
    task = bool(_TASK_RE.search(text))
    payment = bool(_PAY_RE.search(text))
    unusual = bool(_UNUSUAL_PAYMENT_RE.search(text))
    if employment and _FAKE_CHECK_RE.search(text):
        return "job offer uses a check to fund equipment purchases or return money"
    if task and _TASK_DEPOSIT_RE.search(text) and (unusual or _EARNINGS_LURE_RE.search(text)):
        return "paid-task platform requires deposits to continue work or withdraw earnings"
    if employment and _MONEY_MULE_RE.search(text):
        return "job requires personal-account receipt and onward transfer of funds"
    if employment and _RESHIPPING_RE.search(text):
        return "job requires receiving and reshipping packages through a personal address"
    if employment and _APPLICANT_FEE_RE.search(text) and (
        payment or unusual or _NO_INTERVIEW_RE.search(text)
    ) and (
        unusual or _NO_INTERVIEW_RE.search(text) or _PERSONAL_CHANNEL_RE.search(text)
    ):
        return "job applicant must fund fees, training, software, or equipment"
    if employment and _NO_INTERVIEW_RE.search(text) and unusual and (
        payment or _PERSONAL_CHANNEL_RE.search(text)
    ):
        return "instant or guaranteed employment uses an irreversible payment channel"
    return ""


def evaluate_employment_task_scam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type7-employment-task",
        points=100,
        reason=f"Employment or task scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="employment-task-scam",
    )]
