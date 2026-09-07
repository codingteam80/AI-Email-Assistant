from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_VOICEMAIL_RE = re.compile(
    r"\b(?:new|unheard|unread|missed|pending|received|left|recorded|waiting|secure)?\s*"
    r"(?:voice\s*mail|voicemail|voice message|audio message|missed call|call recording|phone message)\b"
    r"|\b(?:caller|extension|phone system)\b.{0,60}\b(?:message|recording|voicemail)\b",
    re.I | re.S,
)
_LISTEN_ACTION_RE = re.compile(
    r"\b(?:play|listen|hear|open|review|retrieve|access|view|read|download)\b.{0,90}"
    r"\b(?:voice\s*mail|voicemail|message|audio|recording|transcript|details?)\b"
    r"|\b(?:voice\s*mail|voicemail|message|audio|recording|transcript|details?)\b.{0,90}"
    r"\b(?:play|listen|hear|open|review|retrieve|access|view|read|download)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:microsoft teams|teams phone|office\s*365|microsoft\s*365|cisco|webex|"
    r"ringcentral|zoom phone|google voice|avaya|8x8)\b",
    re.I,
)
_COMMON_TYPOS = {
    "voicemial": "voicemail", "voicmail": "voicemail", "voicemaill": "voicemail",
    "mesage": "message", "messsage": "message", "lissten": "listen",
    "lisen": "listen", "opne": "open", "retrive": "retrieve",
}
_TRUSTED_VOICEMAIL_HOSTS = (
    "microsoft.com", "office.com", "office365.com", "teams.microsoft.com",
    "cisco.com", "webex.com", "ringcentral.com", "zoom.us", "google.com",
    "avaya.com", "8x8.com",
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
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_VOICEMAIL_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_voicemail_notification_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect voicemail-notification lures with an untrusted playback link."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls or not _VOICEMAIL_RE.search(value) or not _LISTEN_ACTION_RE.search(value):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []
    return [SecurityRuleHit(
        rule_id="phishing.voicemail_notification.playback_lure",
        points=78,
        reason="Voicemail notification directs the recipient to an untrusted message-playback destination",
        categories=("Phishing",),
        strong_flag="voicemail-notification-lure",
    )]
