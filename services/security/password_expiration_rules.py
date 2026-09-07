from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_PASSWORD_CONTEXT_RE = re.compile(
    r"\b(?:password|credential|sign[- ]?in key|login key|access key)\b",
    re.I,
)
_EXPIRATION_RE = re.compile(
    r"\b(?:expire[sd]?|expiring|expiration|renewal|renew|validity|inactive|age limit|"
    r"lifecycle|rotation|rotate|end of (?:its )?validity|no longer be valid)\b",
    re.I,
)
_ACCOUNT_CONTEXT_RE = re.compile(
    r"\b(?:account|mailbox|email|microsoft\s*365|microsoft account|google workspace|"
    r"outlook|identity center|corporate|company|work)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:renew|update|change|rotate|extend|continue|maintain|retain|keep|open|start|review)\b"
    r".{0,90}\b(?:password|credential|account|mailbox|email|access|renewal|rotation|options?|page)\b"
    r"|\b(?:password|credential|account|mailbox|email|access|renewal|rotation|options?|page)\b"
    r".{0,90}\b(?:renew|update|change|rotate|extend|continue|maintain|retain|keep|open|start|review)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:microsoft|microsoft\s*365|outlook|google workspace|identity center)\b",
    re.I,
)
_COMMON_TYPOS = {
    "pasword": "password", "passwrod": "password", "expiraton": "expiration",
    "expier": "expire", "acount": "account", "updat": "update",
    "reched": "reached", "requred": "required", "oepn": "open",
}
_TRUSTED_IDENTITY_HOSTS = (
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
    "google.com", "accounts.google.com",
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


def evaluate_password_expiration_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect password-expiration lures while preserving trusted notifications."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls:
        return []
    if not (_PASSWORD_CONTEXT_RE.search(value) and _EXPIRATION_RE.search(value) and _ACCOUNT_CONTEXT_RE.search(value)):
        return []
    if not _ACTION_RE.search(value):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []
    return [SecurityRuleHit(
        rule_id="phishing.password_expiration.renewal_lure",
        points=78,
        reason="Password-expiration notice directs the recipient to an untrusted credential-renewal destination",
        categories=("Phishing",),
        strong_flag="password-expiration-lure",
    )]
