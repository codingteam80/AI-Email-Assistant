"""Scam/Fraud Type 1: detect fake discounts, coupons, vouchers, and promo codes."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_COUPON_RE = re.compile(
    r"\b(?:discount|coupon|voucher|promo(?:tional)? code|promotion code|rebate|store credit|"
    r"shopping credit|savings code|offer code)\b",
    re.I,
)
_EXPLICIT_FAKE_RE = re.compile(
    r"\b(?:fake|counterfeit|forged|bogus|fraudulent|unauthorized|fabricated|invalid)\b"
    r".{0,80}\b(?:discount|coupon|voucher|promo(?:tional)? code|promotion code|rebate|offer)\b"
    r"|\b(?:discount|coupon|voucher|promo(?:tional)? code|promotion code|rebate|offer)\b"
    r".{0,80}\b(?:is|was|marked|identified as|presented as)?\s*"
    r"(?:fake|counterfeit|forged|bogus|fraudulent|unauthorized|fabricated|invalid)\b",
    re.I | re.S,
)
_CLAIM_RE = re.compile(
    r"\b(?:claim|redeem|activate|unlock|release|receive|get|collect|apply|use)\b",
    re.I,
)
_URGENCY_RE = re.compile(
    r"\b(?:expires? (?:today|now|in \d+ (?:minutes?|hours?))|last chance|limited time|"
    r"act now|immediately|within \d+ (?:minutes?|hours?)|only \d+ (?:minutes?|hours?) left|"
    r"before midnight|final reminder)\b",
    re.I,
)
_DEEP_DISCOUNT_RE = re.compile(
    r"\b(?:8[0-9]|9[0-9]|100)\s*%\s*(?:off|discount|savings?)\b"
    r"|\b(?:save|discounted by)\s*(?:8[0-9]|9[0-9]|100)\s*%\b",
    re.I,
)
_FEE_RE = re.compile(
    r"\b(?:activation|processing|verification|release|redemption|handling|registration) fee\b"
    r"|\b(?:pay|send|transfer)\b.{0,80}\b(?:fee|charge|deposit)\b.{0,100}"
    r"\b(?:coupon|discount|voucher|promo code|offer|shopping credit|store credit|savings|rebate)\b"
    r"|\b(?:coupon|discount|voucher|promo code|offer|shopping credit|store credit|savings|rebate)\b.{0,100}"
    r"\b(?:pay|send|transfer)\b.{0,80}\b(?:fee|charge|deposit)\b",
    re.I | re.S,
)
_SENSITIVE_RE = re.compile(
    r"\b(?:card number|credit card details?|debit card details?|cvv|card security code|"
    r"bank account|banking details?|account password|login password|one[- ]time password|otp|"
    r"authentication code|social security number|tax identification number)\b",
    re.I,
)
_GIFT_CARD_RE = re.compile(
    r"\b(?:buy|purchase|send|provide|share)\b.{0,100}\b(?:gift card|prepaid card)\b"
    r".{0,100}\b(?:code|pin|number|redeem|activate|unlock)\b"
    r"|\b(?:gift card|prepaid card)\b.{0,100}\b(?:code|pin|number)\b"
    r".{0,100}\b(?:coupon|discount|voucher|offer)\b",
    re.I | re.S,
)
_GENERATOR_RE = re.compile(
    r"\b(?:coupon|discount|promo code|voucher) generator\b"
    r"|\bgenerate unlimited (?:coupons?|discount codes?|promo codes?|vouchers?)\b",
    re.I,
)
_GENERATOR_ACTION_RE = re.compile(
    r"\b(?:complet(?:e|es|ed|ing)|finish(?:es|ed|ing)?|submit(?:s|ted|ting)?|"
    r"install(?:s|ed|ing)?|download(?:s|ed|ing)?|enabl(?:e|es|ed|ing)|"
    r"subscrib(?:e|es|ed|ing)|register(?:s|ed|ing)?|pay(?:s|ing|paid)?)\b"
    r".{0,100}\b(?:survey|app|extension|notification|subscription|registration|offer|fee)\b",
    re.I | re.S,
)
_BRAND_DECEPTION_RE = re.compile(
    r"\b(?:not authorized by|not issued by|falsely presented as|pretending to be|"
    r"claims? to be official|unofficial code for)\b.{0,100}"
    r"\b(?:retailer|store|brand|merchant|coupon|discount|voucher|promotion)\b",
    re.I | re.S,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:security awareness|fraud awareness|consumer warning|scam warning|research|analysis|"
    r"incident review|training|simulation|example|detection guidance|fraud prevention|"
    r"do not redeem|do not click|reported as fraud|blocked as fraud|not a live offer)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake discount|fake coupon|coupon fraud|discount fraud|counterfeit voucher|"
    r"forged promo code|fraudulent coupon|coupon scam)\b",
    re.I,
)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "is_fake_coupon", "fake_coupon_detected", "fake_discount_detected",
        "coupon_fraud_detected", "fraudulent_promotion_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("coupon_analysis", "promotion_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_FAKE_RE.search(value):
            return f"scanner fake-discount evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str, *, has_risky_destination: bool) -> str:
    text = str(value or "")
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    coupon = bool(_COUPON_RE.search(text))
    claim = bool(_CLAIM_RE.search(text))
    if _EXPLICIT_FAKE_RE.search(text):
        return "discount, coupon, voucher, or promo code is explicitly fraudulent"
    if coupon and claim and _FEE_RE.search(text):
        return "coupon redemption requires an advance activation or processing fee"
    if coupon and claim and _GIFT_CARD_RE.search(text):
        return "coupon redemption requests transferable gift-card value"
    if coupon and claim and _SENSITIVE_RE.search(text):
        return "coupon redemption requests sensitive payment or account information"
    if coupon and _GENERATOR_RE.search(text) and _GENERATOR_ACTION_RE.search(text):
        return "coupon generator requires an unrelated paid or enrollment action"
    if coupon and _BRAND_DECEPTION_RE.search(text):
        return "coupon is falsely presented as an authorized retailer offer"
    if (
        coupon and claim and has_risky_destination
        and _DEEP_DISCOUNT_RE.search(text) and _URGENCY_RE.search(text)
    ):
        return "extreme discount combines urgent redemption with a risky destination"
    return ""


def evaluate_fake_discount_coupon_rules(
    *, email_data: Mapping, text: str, has_risky_destination: bool
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(
        str(text or ""), has_risky_destination=bool(has_risky_destination)
    )
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type1-fake-discount-coupon",
        points=100,
        reason=f"Fake discount or coupon detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="fake-discount-coupon",
    )]
