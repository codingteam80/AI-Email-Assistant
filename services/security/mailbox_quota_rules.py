from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_MAILBOX_RE = re.compile(
    r"\b(?:mailbox|email account|email storage|mail storage|inbox|outlook|microsoft\s*365|google workspace)\b",
    re.I,
)
_QUOTA_RE = re.compile(
    r"\b(?:quota|storage|capacity|space|limit)\b.{0,75}\b(?:full|reached|exceeded|used|"
    r"nearly full|almost full|at capacity|limit|maximum|remaining|available)\b"
    r"|\b(?:full|reached|exceeded|used|nearly full|almost full|at capacity|maximum)\b.{0,75}"
    r"\b(?:quota|storage|capacity|space|limit)\b"
    r"|\b(?:cannot receive|unable to receive|delivery will stop|incoming mail (?:is|will be) blocked)\b",
    re.I | re.S,
)
_ACTION_RE = re.compile(
    r"\b(?:increase|expand|upgrade|release|restore|manage|review|update|validate|retain|keep|"
    r"free|clear|add|continue|open|view)\b.{0,90}"
    r"\b(?:quota|storage|capacity|space|mailbox|email|mail|messages?|access|page|settings?)\b"
    r"|\b(?:quota|storage|capacity|space|mailbox|email|mail|messages?|access|page|settings?)\b.{0,90}"
    r"\b(?:increase|expand|upgrade|release|restore|manage|review|update|validate|retain|keep|"
    r"free|clear|add|continue|open|view)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:microsoft|microsoft\s*365|office\s*365|outlook|google workspace|gmail|exchange)\b",
    re.I,
)
_COMMON_TYPOS = {
    "mailbxo": "mailbox", "mailbbox": "mailbox", "qouta": "quota",
    "qouta": "quota", "stroage": "storage", "capcity": "capacity",
    "reched": "reached", "exceded": "exceeded", "upgarde": "upgrade",
    "mange": "manage", "oepn": "open", "ful": "full", "mesages": "messages",
}
_TRUSTED_MAIL_HOSTS = (
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "outlook.com", "google.com", "accounts.google.com",
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
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_MAIL_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_mailbox_quota_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect mailbox-quota lures that lead to an untrusted management page."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls or not _MAILBOX_RE.search(value) or not _QUOTA_RE.search(value) or not _ACTION_RE.search(value):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []
    return [SecurityRuleHit(
        rule_id="phishing.mailbox_quota.capacity_lure",
        points=78,
        reason="Mailbox-quota warning directs the recipient to an untrusted storage-management destination",
        categories=("Phishing",),
        strong_flag="mailbox-quota-lure",
    )]
