from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_APP_CONTEXT_RE = re.compile(
    r"\b(?:app|application|integration|connector|service|add[- ]?in|extension|workspace tool|"
    r"productivity tool|cloud tool|document tool)\b",
    re.I,
)
_CONSENT_ACTION_RE = re.compile(
    r"\b(?:approve|accept|grant|authorize|allow|consent|connect|enable)\b.{0,100}"
    r"\b(?:access|permission|permissions|consent|scopes?|account|profile|mailbox|email|files?|"
    r"contacts?|calendar|drive|documents?|data)\b"
    r"|\b(?:access|permission|permissions|consent|scopes?|account|profile|mailbox|email|files?|"
    r"contacts?|calendar|drive|documents?|data)\b.{0,100}"
    r"\b(?:approve|accept|grant|authorize|allow|consent|connect|enable)\b",
    re.I | re.S,
)
_RESOURCE_ACCESS_RE = re.compile(
    r"\b(?:read|view|manage|send|modify|edit|access)\b.{0,90}"
    r"\b(?:mail|email|mailbox|files?|documents?|contacts?|calendar|profile|account|drive|data)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:microsoft|microsoft\s*365|office\s*365|google|google workspace|dropbox|slack|"
    r"salesforce|zoom|adobe|github)\b",
    re.I,
)
_COMMON_TYPOS = {
    "aprove": "approve", "aproval": "approval", "permision": "permission",
    "permisions": "permissions", "autorize": "authorize", "conect": "connect",
    "aplication": "application", "acess": "access", "oepn": "open",
}
_TRUSTED_OAUTH_HOSTS = (
    "microsoftonline.com", "login.microsoftonline.com", "microsoft.com", "office.com",
    "accounts.google.com", "google.com", "slack.com", "dropbox.com", "salesforce.com",
    "zoom.us", "adobe.com", "github.com",
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
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_OAUTH_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_oauth_consent_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect application-consent lures that use an untrusted authorization page."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls or not _APP_CONTEXT_RE.search(value) or not _CONSENT_ACTION_RE.search(value):
        return []
    # A permissions request or an explicit resource-access list establishes the
    # OAuth intent; generic app marketing with a Connect button is insufficient.
    if not (re.search(r"\b(?:permission|permissions|consent|scopes?)\b", value, re.I) or _RESOURCE_ACCESS_RE.search(value)):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []
    return [SecurityRuleHit(
        rule_id="phishing.oauth_consent.permission_lure",
        points=78,
        reason="Application-consent request directs the recipient to an untrusted authorization destination",
        categories=("Phishing",),
        strong_flag="oauth-consent-lure",
    )]
