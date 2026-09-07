"""Spam Type 6: detect outreach sent to harvested or acquired addresses."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:harvested-address spam|scraped-address outreach|purchased contact-list spam|"
    r"address-harvesting spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|consented|opted in|submitted (?:a |the )?contact form|gave (?:us|me) (?:your|this) address|"
    r"business card|direct referral|referred by|requested contact|existing relationship|current customer|"
    r"existing vendor|privacy request|incident report|security awareness|training|simulation|example|"
    r"analysis|sender allowlisted|trusted sender|false positive)\b",
    re.I,
)
_CONTENT_CLEAN_RE = re.compile(
    r"\b(?:not spam|consented|opted in|submitted (?:a |the )?contact form|gave (?:us|me) (?:your|this) address|"
    r"business card|direct referral|referred by|requested contact|existing relationship|current customer|"
    r"existing vendor|privacy request|incident report|security awareness|training|simulation|"
    r"sender allowlisted|trusted sender|false positive)\b",
    re.I,
)
_HARVEST_SOURCE_RE = re.compile(
    r"\b(?:found your (?:email|address) in (?:a |the )?public directory|"
    r"collected your (?:email|address) from (?:your|a) website|"
    r"obtained your (?:email|contact) from (?:an |a )?online database|"
    r"sourced your (?:email|address|contact) from public records|"
    r"scraped (?:your address|email addresses) from (?:business |company )?(?:pages|websites|listings)|"
    r"acquired (?:your address|this contact|our list) from (?:a |an )?data provider|"
    r"purchased (?:your contact|this address|a contact list)|"
    r"compiled (?:your email|email addresses) from online listings|"
    r"guessed your work address (?:from|using) (?:the |your )?company domain|"
    r"extracted your contact from (?:a |the )?directory|"
    r"publicly listed email address|contact database supplied your address|"
    r"address was selected from public records)\b",
    re.I,
)
_OUTREACH_ACTION_RE = re.compile(
    r"\b(?:reaching out|contacting you|sending you (?:this|an) (?:offer|introduction|message)|"
    r"introduce (?:our|a) (?:company|service|platform)|share (?:our|a) (?:service|offer|proposal)|"
    r"invite you to|promote (?:our|a) (?:service|product|plan)|request (?:a )?(?:reply|call|meeting)|"
    r"ask whether you are interested|offer you (?:a |our )?(?:service|product|plan))\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "an introduction from our database",
    "business-page outreach",
    "a message to your likely work address",
    "directory contact inquiry",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "harvested_address_spam_detected", "scraped_address_outreach_detected",
        "purchased_contact_list_detected", "address_harvesting_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner harvested-address evidence: {value[:120]}"
    source = str(email_data.get("recipient_address_source") or email_data.get("contact_source") or "").casefold()
    if source in {"scraped", "harvested", "purchased list", "public-directory scrape", "guessed address"}:
        return f"provider reports recipient address source: {source}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CONTENT_CLEAN_RE.search(text):
        return ""
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS:
        return "reported harvested-address subject recognized before full body synchronization"
    if _HARVEST_SOURCE_RE.search(text) and _OUTREACH_ACTION_RE.search(text):
        return "sender identifies a harvested address source and initiates unsolicited outreach"
    return ""


def evaluate_harvested_address_spam_rules(*, email_data: Mapping, text: str) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type6-harvested-address",
        points=100,
        reason=f"Harvested-address spam detected ({reason})",
        categories=("Spam",),
        strong_flag="harvested-address-spam",
    )]
