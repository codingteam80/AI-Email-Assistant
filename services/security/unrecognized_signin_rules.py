from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_UNRECOGNIZED_ACTIVITY_RE = re.compile(
    r"\b(?:new|unrecogni[sz]ed|unfamiliar|unknown|different|another|not previously associated)\b"
    r".{0,100}\b(?:sign[- ]?in|log[- ]?in|login|session|device|browser|location|network|access|activity)\b"
    r"|\b(?:sign[- ]?in|log[- ]?in|login|session|device|browser|location|network|access|activity)\b"
    r".{0,100}\b(?:new|unrecogni[sz]ed|unfamiliar|unknown|different|another|not previously associated)\b"
    r"|\b(?:session|device|browser|access|activity)\b.{0,45}\bnot\s+(?:recognized|recognised|known|in your recent (?:device )?list)\b"
    r"|\b(?:was(?:n['’]t| not) you|could not be (?:recognized|recognised|matched)|we have not seen before)\b",
    re.I | re.S,
)
_ACCOUNT_CONTEXT_RE = re.compile(
    r"\b(?:account|mailbox|email|microsoft\s*365|microsoft account|google account|google workspace|"
    r"apple id|outlook|identity center|authenticator|profile)\b",
    re.I,
)
_REVIEW_ACTION_RE = re.compile(
    r"\b(?:review|check|inspect|view|see|manage|open|read)\b.{0,80}"
    r"\b(?:activity|event|attempt|session|request|device|access|record|details?|login|sign[- ]?in)\b"
    r"|\b(?:activity|event|attempt|session|request|device|access|record|details?|login|sign[- ]?in)\b.{0,80}"
    r"\b(?:review|check|inspect|view|see|manage|open|read)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:microsoft|microsoft\s*365|outlook|google|google workspace|apple|apple id|"
    r"identity center|authenticator)\b",
    re.I,
)
_COMMON_TYPOS = {
    "sesson": "session",
    "opend": "opened",
    "unkown": "unknown",
    "chek": "check",
}
_TRUSTED_IDENTITY_HOSTS = (
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
    "google.com", "accounts.google.com", "apple.com", "icloud.com",
)
_CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}


def _host(url: str) -> str:
    try:
        return (urlparse(str(url or "")).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _trusted_host(host: str) -> bool:
    value = str(host or "").casefold().strip(".")
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_IDENTITY_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_unrecognized_signin_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect fake unrecognized-sign-in alerts without flagging trusted alerts."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)

    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls:
        return []
    if not _UNRECOGNIZED_ACTIVITY_RE.search(value) or not _ACCOUNT_CONTEXT_RE.search(value):
        return []
    if not _REVIEW_ACTION_RE.search(value):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []

    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []

    return [SecurityRuleHit(
        rule_id="phishing.unrecognized_signin.activity_lure",
        points=78,
        reason="Unrecognized sign-in alert directs the recipient to an untrusted account-activity destination",
        categories=("Phishing",),
        strong_flag="unrecognized-signin-lure",
    )]
