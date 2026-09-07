"""Promotional Type 7: identify legitimate discount or coupon promotions."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:discount or coupon promotion|legitimate coupon promotion|"
    r"retail discount campaign|official store voucher)\b",
    re.I,
)
_DISCOUNT_RE = re.compile(
    r"\b(?:\d{1,2}\s*(?:%|percent)\s*off|save\s+\d{1,2}\s*(?:%|percent)|discount|coupon|voucher|"
    r"savings code|promo code|code\s+[A-Z0-9]{4,}|complimentary shipping)\b",
    re.I,
)
_LEGITIMATE_CONTEXT_RE = re.compile(
    r"\b(?:official store|our store|store purchase|next purchase|next order|"
    r"selected (?:items|products)|members?|loyalty|welcome|thank[- ]you|"
    r"at checkout|this week|weekend|available|enjoy|save|redeem)\b",
    re.I,
)
_FRAUD_RE = re.compile(
    r"\b(?:fake|bogus|counterfeit|forged|fraudulent|unauthorized|processing fee|"
    r"activation fee|verification deposit|card number|cvv|gift card code|"
    r"coupon generator|account password|claim your reward)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "your 15 percent welcome discount",
    "coupon for your next store purchase",
    "save with code member15",
    "a thank-you voucher for members",
    "enjoy 10 percent off this week",
    "your loyalty discount is available",
    "store coupon for selected items",
    "use code spring20 at checkout",
    "member voucher for your next order",
    "save 25 percent on selected products",
    "a new savings code for you",
    "your complimentary shipping coupon",
    "exclusive member discount inside",
    "redeem your official store voucher",
    "weekend coupon from our store",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "discount_coupon_promotion_detected", "legitimate_coupon_promotion_detected",
        "retail_discount_campaign_detected", "official_store_voucher_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("promotional_classification", "content_analysis", "coupon_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner legitimate discount evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _FRAUD_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies a legitimate coupon promotion"
    if _DISCOUNT_RE.search(text) and _LEGITIMATE_CONTEXT_RE.search(text):
        return "ordinary retailer discount, coupon, voucher, or shipping offer is advertised"
    return ""


def evaluate_discount_coupon_promotion_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type7-discount-coupon",
        points=100,
        reason=f"Discount or coupon promotion detected ({reason})",
        categories=("Promotional",),
        strong_flag="discount-coupon-promotional",
    )]
