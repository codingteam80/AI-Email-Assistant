"""Promotional Type 12: identify legitimate abandoned-cart or browse reminders."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:abandoned[- ]cart or browse reminder|abandoned[- ]cart reminder|"
    r"browse reminder|saved cart promotion|recently viewed reminder)\b",
    re.I,
)
_CART_OR_BROWSE_RE = re.compile(
    r"\b(?:left (?:items?|products?) in your (?:cart|basket)|"
    r"(?:cart|basket) (?:is )?(?:still )?(?:saved|waiting)|"
    r"still in (?:your|the) cart|complete your cart|"
    r"continue where you left off|recently viewed|recent product views?|"
    r"items? you viewed|revisit (?:these )?items?|take another look|"
    r"still considering|recent store visit|last store visit|saved items?)\b",
    re.I,
)
_COMMERCIAL_CONTEXT_RE = re.compile(
    r"\b(?:items?|products?|cart|basket|store|shopping|collection|"
    r"browsing|viewed|purchase|checkout|saved)\b",
    re.I,
)
_EXCLUSION_RE = re.compile(
    r"\b(?:verify your account|confirm your identity|password|passcode|otp|"
    r"security alert|account suspended|payment overdue|past due|invoice|debt|"
    r"medical appointment|calendar reminder|unfinished document|pending task|"
    r"wire transfer|bank account|card number|cvv)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "you left items in your cart",
    "your shopping cart is still saved",
    "complete your recent store visit",
    "items you viewed are still available",
    "take another look at your saved items",
    "your basket is waiting",
    "continue where you left off",
    "remember these products from your visit",
    "return to your recently viewed items",
    "your selected items are still in the cart",
    "finish browsing your saved collection",
    "a reminder about your recent product views",
    "revisit items from your last store visit",
    "complete your cart when you are ready",
    "still considering these products",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "abandoned_cart_browse_reminder_detected", "abandoned_cart_reminder_detected",
        "browse_reminder_detected", "recently_viewed_reminder_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "promotional_classification", "content_analysis",
        "cart_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and _ANALYSIS_RE.search(value):
            return f"scanner cart-or-browse evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    if _EXCLUSION_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject identifies an abandoned-cart or browse reminder"
    if _CART_OR_BROWSE_RE.search(text) and _COMMERCIAL_CONTEXT_RE.search(text):
        return "a saved cart, viewed product, or recent store-browsing session is recalled"
    return ""


def evaluate_abandoned_cart_browse_reminder_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="promotional-type12-abandoned-cart-browse",
        points=100,
        reason=f"Abandoned-cart or browse reminder detected ({reason})",
        categories=("Promotional",),
        strong_flag="abandoned-cart-browse-promotional",
    )]
