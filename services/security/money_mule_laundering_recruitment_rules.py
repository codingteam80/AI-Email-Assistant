"""Scam/Fraud Type 15: detect money-mule and laundering recruitment."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_RECRUITMENT_RE = re.compile(
    r"\b(?:job|position|role|employment|work[- ]from[- ]home|remote work|opportunity|recruiter|"
    r"hiring|agent|payment processor|payment processing agent|financial agent|transfer agent|"
    r"account manager|money transfer representative|collection agent|local representative|"
    r"cash-out agent|crypto exchange assistant|personal assistant)\b",
    re.I,
)
_RECEIVE_RE = re.compile(
    r"\b(?:receiv\w*|accept\w*|collect\w*|deposit\w*|have deposited|allow\w*|rout\w*)\b.{0,120}"
    r"\b(?:money|funds?|payments?|transfers?|wires?|checks?|cheques?|cash|cryptocurrency|crypto|"
    r"bitcoin|client funds?|customer payments?|company payments?)\b"
    r"|\b(?:money|funds?|payments?|transfers?|wires?|checks?|cash|crypto)\b.{0,100}"
    r"\b(?:into|through|using)\b.{0,60}\b(?:your|personal)\b.{0,30}\b(?:account|wallet|payment app)\b",
    re.I | re.S,
)
_FORWARD_RE = re.compile(
    r"\b(?:forward\w*|send\w*|sent|transfer\w*|wir(?:e|es|ed|ing)|remit\w*|mov\w*|withdraw\w*|"
    r"cash(?:es|ed|ing)? out|convert\w*|exchang\w*|purchas\w*|buy|buys|buying|bought)\b"
    r".{0,140}\b(?:money|funds?|payments?|balance|portion|remainder|cash|cryptocurrency|crypto|"
    r"bitcoin|gift[- ]cards?|prepaid cards?|another account|overseas account|wallet)\b"
    r"|\b(?:after|once|then)\b.{0,80}\b(?:forward\w*|send\w*|transfer\w*|wir\w*|withdraw\w*|convert\w*|cash out)\b",
    re.I | re.S,
)
_PERSONAL_ACCOUNT_RE = re.compile(
    r"\b(?:your|personal)\s+(?:bank |checking |savings |crypto |cryptocurrency |payment-app )?"
    r"(?:account|wallet)|own bank account|own account|personal payment app|your payment app|"
    r"open (?:a |an )?(?:new )?(?:bank|crypto|cryptocurrency|payment-app) account|"
    r"accounts? in your name\b",
    re.I,
)
_COMMISSION_RE = re.compile(
    r"\b(?:keep|retain|earn|receive|take)\b.{0,80}\b(?:commission|fee|percentage|percent|%|cut|share)\b"
    r"|\bfor (?:a |the )?(?:commission|processing fee|transfer fee|percentage|cut)\b"
    r"|\b(?:commission|processing fee|transfer fee)\b.{0,80}\b(?:per transfer|per payment|for yourself|"
    r"is yours|you keep)\b",
    re.I | re.S,
)
_LAUNDERING_RE = re.compile(
    r"\b(?:split (?:the )?(?:money|funds?|payments?)|multiple accounts?|avoid (?:the )?bank|"
    r"avoid reporting|do not mention|don't mention|no questions asked|keep the source secret|"
    r"hide the source|clean (?:the )?(?:money|funds?)|layer (?:the )?(?:money|transactions?)|"
    r"convert (?:the )?(?:money|funds?|payments?) to (?:crypto|bitcoin|gift cards?|cash)|"
    r"send (?:the )?(?:money|funds?) overseas|use different accounts?|below reporting limits?)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:money[- ]mule scam|money[- ]mule recruitment|mule account recruitment|"
    r"laundering recruitment|money laundering job|financial-agent mule|payment-processor mule)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|anti[- ]money[- ]laundering training|aml training|"
    r"licensed money-services business|regulated payment processor|company-owned account|"
    r"corporate settlement account|no personal accounts? (?:are|is) used|"
    r"do not use (?:a |your )?personal account|no onward transfer (?:is )?requested|"
    r"verified payroll deposit|family reimbursement)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:money[- ]mule recruitment|money[- ]mule scheme|laundering recruitment|"
    r"money laundering job|payment-processor mule|financial-agent mule)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "money_mule_detected", "money_mule_recruitment_detected",
        "laundering_recruitment_detected", "mule_account_detected",
        "payment_processor_mule_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("money_mule_analysis", "laundering_analysis", "recruitment_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner money-mule/laundering evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes money-mule or laundering recruitment"
    recruitment = bool(_RECRUITMENT_RE.search(text))
    receiving = bool(_RECEIVE_RE.search(text))
    forwarding = bool(_FORWARD_RE.search(text))
    personal_account = bool(_PERSONAL_ACCOUNT_RE.search(text))
    commission = bool(_COMMISSION_RE.search(text))
    laundering = bool(_LAUNDERING_RE.search(text))
    if recruitment and receiving and forwarding and personal_account:
        return "recruited worker must receive and forward third-party funds through a personal account"
    if receiving and forwarding and personal_account and (commission or laundering):
        return "personal account is used to relay or convert funds for commission or concealment"
    if recruitment and personal_account and forwarding and (commission or laundering):
        return "payment-processing role recruits the recipient to move or disguise money"
    if recruitment and receiving and laundering:
        return "recruitment instructions structure, convert, or conceal received funds"
    return ""


def evaluate_money_mule_laundering_recruitment_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type15-money-mule-laundering-recruitment",
        points=100,
        reason=f"Money-mule or laundering recruitment detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="money-mule-laundering-recruitment",
    )]
