"""Scam/Fraud Type 14: detect real-estate and high-value transaction fraud."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_REAL_ESTATE_RE = re.compile(
    r"\b(?:real estate|property|home|house|apartment|condominium|condo|villa|land|lot|"
    r"property purchase|property sale|closing|escrow|title company|title agent|realtor|"
    r"real-estate agent|estate agent|mortgage payoff|down payment|earnest money|closing funds?|"
    r"settlement funds?|deed|lease deposit|rental deposit)\b",
    re.I,
)
_HIGH_VALUE_RE = re.compile(
    r"\b(?:high[- ]value (?:sale|purchase|transaction|item|asset)|luxury (?:car|vehicle|watch|goods?)|"
    r"vehicle|car|motorcycle|yacht|boat|vessel|aircraft|jewelry|diamond|gold|fine art|artwork|"
    r"collectible|heavy equipment|industrial equipment|machinery|business acquisition|company purchase|"
    r"asset purchase|equipment purchase)\b",
    re.I,
)
_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:send\w*|wir(?:e|es|ed|ing)|transfer\w*|pay|pays|paid|paying|remit\w*|deposit\w*|"
    r"release\w*|fund\w*|submit\w*)\b.{0,150}\b(?:funds?|money|payment|deposit|balance|"
    r"purchase price|closing funds?|settlement funds?|escrow|down payment|earnest money|"
    r"bank account|beneficiary|seller|wallet|bitcoin|cryptocurrency|crypto)\b"
    r"|\b(?:funds?|money|payment|deposit|earnest money|closing funds?|settlement funds?)\b"
    r".{0,70}\b(?:wired|transferred|sent|paid|remitted)\b",
    re.I | re.S,
)
_RISKY_ROUTING_RE = re.compile(
    r"\b(?:new|updated|revised|changed|replacement|alternate|different|personal|third[- ]party)\b"
    r".{0,90}\b(?:bank account|account|beneficiary|wire instructions?|payment details?|"
    r"bank details?|wallet)\b"
    r"|\b(?:outside|bypass|avoid|without) (?:the )?(?:escrow|closing portal|marketplace|dealer|"
    r"title company|solicitor account)\b"
    r"|\b(?:pay|send|wire|transfer)\b.{0,90}\b(?:seller directly|owner directly|directly to (?:the )?(?:property )?owner|personal account|"
    r"third[- ]party account|private wallet|bitcoin|cryptocurrency|crypto wallet)\b"
    r"|\b(?:disregard|ignore|do not use|don't use)\b.{0,80}\b(?:old|previous|original)\b"
    r".{0,60}\b(?:wire instructions?|account|beneficiary|payment details?)\b",
    re.I | re.S,
)
_NO_VERIFICATION_RE = re.compile(
    r"\b(?:no inspection|no viewing|without inspection|without viewing|cannot inspect|can't inspect|"
    r"cannot view|can't view|do not contact|don't contact|do not call|don't call|do not verify|"
    r"no need to verify|seller unavailable|owner abroad|title company unavailable|"
    r"refuses? (?:an )?(?:inspection|viewing|meeting)|no title documents?|no registration|"
    r"no proof of ownership|no escrow|escrow is unnecessary|skip the escrow|"
    r"before (?:an |the )?(?:property )?(?:inspection|viewing|title check|ownership check))\b",
    re.I,
)
_PRESSURE_RE = re.compile(
    r"\b(?:urgent|urgently|immediately|right now|today|asap|within (?:an hour|one hour|24 hours)|"
    r"before closing|before cutoff|last-minute change|last minute change|another buyer is waiting|"
    r"lose the property|lose the deal|hold the property|reserve the vehicle|final opportunity)\b",
    re.I,
)
_EXPLICIT_RE = re.compile(
    r"\b(?:real[- ]estate fraud|real[- ]estate scam|property fraud|property scam|closing fraud|"
    r"escrow fraud|title-company fraud|closing-wire scam|high[- ]value transaction fraud|"
    r"vehicle purchase scam|luxury-goods scam)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:scam warning|fraud awareness|security awareness|consumer warning|research|analysis|"
    r"training|simulation|example|incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|fraud prevention|confirmed in person|verified title company|"
    r"regulated escrow|licensed escrow|authenticated closing portal|independent inspection completed|"
    r"title search completed|proof of ownership verified|registered dealer|protected marketplace|"
    r"no change to (?:the )?wire instructions?|unchanged wire instructions?)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:real[- ]estate fraud|property closing scam|escrow fraud|closing-wire fraud|"
    r"high[- ]value transaction fraud|vehicle purchase scam|luxury transaction fraud)\b",
    re.I,
)


def _canonical_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "real_estate_fraud_detected", "property_fraud_detected", "closing_fraud_detected",
        "escrow_fraud_detected", "high_value_transaction_fraud_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("real_estate_analysis", "property_analysis", "transaction_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_RE.search(value):
            return f"scanner real-estate/high-value evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = _canonical_text(value)
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    if _EXPLICIT_RE.search(text):
        return "message explicitly describes real-estate or high-value transaction fraud"
    real_estate = bool(_REAL_ESTATE_RE.search(text))
    high_value = bool(_HIGH_VALUE_RE.search(text))
    payment = bool(_PAYMENT_ACTION_RE.search(text))
    risky_routing = bool(_RISKY_ROUTING_RE.search(text))
    no_verification = bool(_NO_VERIFICATION_RE.search(text))
    pressure = bool(_PRESSURE_RE.search(text))
    if real_estate and payment and risky_routing and (pressure or no_verification):
        return "property, closing, title, or escrow funds are routed through unsafe instructions"
    if real_estate and payment and no_verification and pressure:
        return "property deposit is demanded before viewing, title, ownership, or escrow verification"
    if high_value and payment and risky_routing and (no_verification or pressure):
        return "high-value purchase requires unsafe payment without normal transaction protection"
    if high_value and payment and no_verification and pressure:
        return "high-value seller pressures payment while refusing inspection or ownership verification"
    return ""


def evaluate_real_estate_high_value_transaction_fraud_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type14-real-estate-high-value-transaction",
        points=100,
        reason=f"Real-estate or high-value transaction fraud detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="real-estate-high-value-transaction-fraud",
    )]
