"""Scam/Fraud Type 9: detect emergency and confidence scams."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_RELATION_RE = re.compile(
    r"\b(?:grandchild|grandson|granddaughter|grandparent|son|daughter|mother|father|mom|mum|dad|"
    r"brother|sister|nephew|niece|cousin|uncle|aunt|spouse|husband|wife|partner|relative|"
    r"family member|friend|close friend|colleague|coworker|online friend|romantic partner|"
    r"fiance|fiancee|someone you trust)\b",
    re.I,
)
_EMERGENCY_RE = re.compile(
    r"\b(?:emergency|urgent help|accident|hospital|medical treatment|surgery|injured|arrested|"
    r"detained|jail|bail|lawyer|attorney|police|court|stranded|stuck abroad|lost passport|"
    r"missed flight|travel problem|robbed|stolen wallet|kidnapped|ransom|crisis|emergency room|"
    r"cannot get home|need to get home)\b",
    re.I,
)
_CONFIDENCE_RE = re.compile(
    r"\b(?:trust me|you can trust me|between friends|because we are close|our relationship|"
    r"we have been talking|we've been talking|known each other online|online relationship|"
    r"romantic relationship|promise to repay|pay you back|temporary favor|personal favor)\b",
    re.I,
)
_PAYMENT_RE = re.compile(
    r"\b(?:send|transfer|wire|pay|buy|purchase|provide)\b.{0,130}"
    r"\b(?:money|funds?|cash|payment|bail|hospital bill|medical bill|lawyer fee|legal fee|"
    r"gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto|money transfer)\b"
    r"|\b(?:needs?|requires?|requests?|asks? for)\b.{0,100}\b(?:money|funds?|cash|payment|"
    r"bail|hospital bill|medical bill|lawyer fee|legal fee|gift[- ]cards?|prepaid "
    r"(?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto|money transfer|cash courier)\b",
    re.I | re.S,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]cards?|prepaid (?:cards?|vouchers?)|bitcoin|cryptocurrency|crypto(?: wallet)?|"
    r"western union|moneygram|money transfer|cash courier|friends and family|personal account)\b",
    re.I,
)
_SECRECY_RE = re.compile(
    r"\b(?:keep (?:this|it|the matter) secret|do not tell anyone|don't tell anyone|"
    r"do not tell (?:my|your|the) (?:parents?|family|spouse|boss)|between us|strictly confidential|"
    r"please be discreet|no one else can know|keep this private)\b",
    re.I,
)
_NO_VERIFY_RE = re.compile(
    r"\b(?:do not call|don't call|cannot call|can't call|phone is broken|phone was stolen|"
    r"do not contact|don't contact|do not verify|no time to verify|cannot speak|can't speak|"
    r"text only|message only|lawyer says not to contact)\b",
    re.I,
)
_URGENCY_RE = re.compile(
    r"\b(?:immediately|right now|within (?:an hour|one hour|today|24 hours)|before it is too late|"
    r"time is running out|urgent|as soon as possible|asap|today)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:emergency scam|grandparent scam|grandchild scam|family emergency scam|"
    r"confidence scam|romance confidence scam|stranded traveler scam|bail money scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not send|fraud prevention|verified with (?:the )?family|"
    r"confirmed by phone|official hospital portal|official court portal|documented emergency plan|"
    r"no money (?:is )?requested|no payment (?:is )?requested)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:emergency scam|grandparent scam|family emergency fraud|confidence scam|"
    r"stranded traveler scam|bail money scam)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "emergency_scam_detected", "confidence_scam_detected", "grandparent_scam_detected",
        "family_emergency_scam_detected", "bail_money_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("emergency_analysis", "confidence_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner emergency/confidence evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes an emergency or confidence scam"
    relation = bool(_RELATION_RE.search(text))
    emergency = bool(_EMERGENCY_RE.search(text))
    confidence = bool(_CONFIDENCE_RE.search(text))
    payment = bool(_PAYMENT_RE.search(text))
    unusual = bool(_UNUSUAL_PAYMENT_RE.search(text))
    secrecy = bool(_SECRECY_RE.search(text))
    no_verify = bool(_NO_VERIFY_RE.search(text))
    urgency = bool(_URGENCY_RE.search(text))
    if relation and emergency and payment and (unusual or secrecy or no_verify):
        return "family, friend, or trusted-contact emergency demands risky payment"
    if emergency and payment and unusual and (secrecy or no_verify or urgency):
        return "urgent medical, legal, bail, or travel crisis uses an irreversible payment method"
    if relation and confidence and payment and unusual and (urgency or secrecy):
        return "trust relationship is exploited for an urgent irreversible payment"
    if confidence and emergency and payment and (unusual or secrecy or no_verify):
        return "confidence relationship is used to support a fabricated emergency payment"
    return ""


def evaluate_emergency_confidence_scam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type9-emergency-confidence",
        points=100,
        reason=f"Emergency or confidence scam detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="emergency-confidence-scam",
    )]
