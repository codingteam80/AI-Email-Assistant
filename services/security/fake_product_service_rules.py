"""Scam/Fraud Type 2: detect fake products, listings, and services."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_PRODUCT_SERVICE_RE = re.compile(
    r"\b(?:product|item|goods?|order|listing|merchandise|device|equipment|vehicle|rental|"
    r"camera|drone|laptop|computer|tablet|smartphone|phone|console|watch|jewelry|furniture|"
    r"appliance|electronics?|machinery|motorcycle|boat|vessel|compressor|mixer|oven|boiler|"
    r"apartment|condominium|bungalow|villa|property|lease|tenancy|ticket|reservation|booking|"
    r"subscription|license|warranty|repair|maintenance|installation|tour|travel|charter|journey|"
    r"consultancy|consulting|advisory|recruitment|membership|delivery service|support service|"
    r"consulting service|service package|vendor|supplier|seller|contractor|operator|provider)\b",
    re.I,
)
_EXPLICIT_FAKE_RE = re.compile(
    r"\b(?:fake|counterfeit|forged|bogus|fraudulent|nonexistent|non-existent|phantom|fictitious|sham|"
    r"invented|fabricated|never existed|does not exist)\b.{0,100}\b(?:product|item|goods?|order|"
    r"listing|merchandise|device|equipment|camera|drone|laptop|computer|tablet|smartphone|phone|"
    r"console|watch|jewelry|furniture|appliance|electronics?|machinery|motorcycle|vehicle|rental|"
    r"apartment|condominium|villa|property|ticket|reservation|"
    r"booking|subscription|license|warranty|repair|maintenance|installation|service|vendor|supplier|"
    r"seller|contractor|company|operator|provider|consultancy|consultant|advisory|agency)\b"
    r"|\b(?:product|item|goods?|order|listing|merchandise|device|equipment|vehicle|rental|"
    r"camera|drone|laptop|computer|tablet|smartphone|phone|console|watch|jewelry|furniture|"
    r"appliance|electronics?|machinery|motorcycle|apartment|condominium|villa|property|ticket|"
    r"reservation|booking|subscription|license|warranty|repair|"
    r"maintenance|installation|service|vendor|supplier|seller|contractor|company|operator|provider|"
    r"consultancy|consultant|advisory|agency)\b.{0,100}"
    r"\b(?:is|was|are|were|proved to be|identified as)?\s*(?:fake|counterfeit|forged|bogus|"
    r"fraudulent|nonexistent|non-existent|phantom|fictitious|sham|invented|fabricated|"
    r"does not exist|never existed)\b",
    re.I | re.S,
)
_ADVANCE_PAYMENT_RE = re.compile(
    r"\b(?:pay|pays|paying|paid|send|sends|sending|sent|transfer|transfers|transferring|transferred)\b"
    r".{0,100}\b(?:upfront|in advance|advance payment|full payment|"
    r"deposit|reservation fee|booking fee|service fee|release fee|holding fee|security fee)\b"
    r"|\b(?:pay|pays|paying|paid)\b.{0,100}\bin full\b"
    r"|\b(?:upfront|advance|full) payment\b"
    r"|\b(?:deposit|reservation fee|booking fee|service fee|release fee|holding fee|security fee)\b.{0,100}"
    r"\b(?:before|to)\b.{0,80}\b(?:ship|deliver|dispatch|release|reserve|book|start|activate)\b"
    r"|\b(?:requires?|demands?|requests?|asks? for|insists? on)\b.{0,100}"
    r"\b(?:payment|deposit|fee|gift[- ]card|prepaid (?:card|voucher)|bitcoin|cryptocurrency|"
    r"crypto|wire transfer|money transfer)\b.{0,100}\b(?:before|prior to)\b",
    re.I | re.S,
)
_UNUSUAL_PAYMENT_RE = re.compile(
    r"\b(?:gift[- ]card|prepaid (?:card|voucher)|bitcoin|cryptocurrency|crypto wallet|wire transfer|"
    r"money transfer|western union|moneygram|payment app|friends and family payment)\b",
    re.I,
)
_OFF_PLATFORM_RE = re.compile(
    r"\b(?:pay outside|complete payment outside|move (?:the )?(?:sale|payment) outside|"
    r"move (?:the )?(?:[a-z][\w-]*\s+){1,3}(?:sale|payment) outside|"
    r"bypass (?:the )?(?:marketplace|platform|checkout|escrow)|avoid (?:the )?(?:marketplace|"
    r"platform|checkout|escrow)|pay (?:the )?seller directly|direct payment only|"
    r"do not use (?:the )?(?:marketplace|platform|checkout|escrow)|"
    r"(?:leave|leaving|move|moving|take|taking) (?:the )?(?:sale|purchase|transaction|payment )?"
    r"(?:away from|off|outside)?\s*(?:the )?(?:marketplace|platform)|"
    r"direct payment (?:outside|off|away from) (?:the )?(?:marketplace|platform)|"
    r"payment (?:sent|made|paid) (?:directly )?(?:outside|off|away from) (?:the )?"
    r"(?:marketplace|platform))\b",
    re.I,
)
_DIRECT_PAYMENT_RE = re.compile(
    r"\b(?:pay (?:the )?seller directly|send (?:the )?seller direct payment|"
    r"direct payment (?:to (?:the )?seller )?only)\b",
    re.I,
)
_NO_VERIFICATION_RE = re.compile(
    r"\b(?:cannot|can't|unable to|not allowed to|no need to)\b.{0,80}\b(?:inspect|view|visit|"
    r"test|verify|meet|call|video call|see the item|see the property)\b"
    r"|\b(?:stock photos? only|no inspection|no viewing|no pickup|seller (?:is )?unavailable|"
    r"provider (?:is )?unavailable|service begins only after payment)\b"
    r"|\b(?:refuses?|declines?|will not|won't|withholds?|withholding)\b.{0,110}"
    r"\b(?:provide|allow|permit|arrange|show|confirm|inspect|view|visit|meet|authenticate|verify|"
    r"records?|lease|license|credentials?|address|quotation|proposal|itinerary|terms|title|"
    r"registration|serial number)\b",
    re.I | re.S,
)
_DELIVERY_RE = re.compile(
    r"\b(?:ship(?:s|ped|ping)?|deliver(?:s|ed|ing)?|dispatch(?:es|ed|ing)?|"
    r"releas(?:e|es|ed|ing)|reserv(?:e|es|ed|ing)|book(?:s|ed|ing)?|"
    r"start(?:s|ed|ing)?|activat(?:e|es|ed|ing)|send(?:s|ing)?|sent|"
    r"provid(?:e|es|ed|ing)|perform(?:s|ed|ing)?|reservation|booking|appointment|allocation)\b",
    re.I,
)
_REFUND_RE = re.compile(
    r"\b(?:guaranteed refund|fully refundable|refund after delivery|deposit returned after|"
    r"payment will be refunded)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:consumer warning|scam warning|fraud awareness|security awareness|research|analysis|"
    r"(?:security|fraud|scam|marketplace) (?:awareness )?training|simulation|example|"
    r"incident review|detection guidance|reported as fraud|"
    r"blocked as fraud|do not pay|do not purchase|marketplace safety)\b",
    re.I,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:fake product|fake service|product scam|service scam|fraudulent listing|"
    r"nonexistent product|phantom service|counterfeit goods scam)\b",
    re.I,
)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "is_fake_product", "is_fake_service", "fake_product_detected",
        "fake_service_detected", "fraudulent_listing_detected",
        "product_service_scam_detected",
    ):
        value = email_data.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("product_analysis", "service_analysis", "listing_analysis", "fraud_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if not value or _CLEAN_CONTEXT_RE.search(value):
            continue
        if _ANALYSIS_RE.search(value) or _EXPLICIT_FAKE_RE.search(value):
            return f"scanner fake-product/service evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str) -> str:
    text = str(value or "")
    if _CLEAN_CONTEXT_RE.search(text):
        return ""
    product_service = bool(_PRODUCT_SERVICE_RE.search(text))
    advance = bool(_ADVANCE_PAYMENT_RE.search(text))
    unusual_payment = bool(_UNUSUAL_PAYMENT_RE.search(text))
    if _EXPLICIT_FAKE_RE.search(text):
        return "product, listing, or service is explicitly fake or nonexistent"
    if product_service and advance and unusual_payment and _DELIVERY_RE.search(text):
        return "product or service requires risky irreversible advance payment"
    if product_service and _OFF_PLATFORM_RE.search(text) and (
        advance or unusual_payment or _DIRECT_PAYMENT_RE.search(text)
    ):
        return "seller redirects payment outside marketplace or escrow protections"
    if product_service and advance and _NO_VERIFICATION_RE.search(text):
        return "advance payment is demanded while inspection or provider verification is refused"
    if product_service and unusual_payment and _NO_VERIFICATION_RE.search(text) and _REFUND_RE.search(text):
        return "unverifiable product or service uses irreversible payment and a false refund assurance"
    return ""


def evaluate_fake_product_service_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _behavior_reason(str(text or ""))
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="scam-type2-fake-product-service",
        points=100,
        reason=f"Fake product or service detected ({reason})",
        categories=("Scam / Fraud",),
        strong_flag="fake-product-service",
    )]
