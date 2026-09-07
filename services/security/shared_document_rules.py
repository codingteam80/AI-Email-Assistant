from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_SHARED_DOCUMENT_RE = re.compile(
    r"\b(?:(?:shared|sent)\s+(?:a|an|the)?\s*(?:secure|confidential|encrypted|protected)?\s*"
    r"(?:(?:pdf|policy|contract|invoice|project|review|research)\s+)?(?:document|file|folder|spreadsheet|presentation|invoice|contract|acknowledgment|packet|materials?)\s+(?:with|to)\s+you|"
    r"(?:(?:pdf|policy|contract|invoice|project|review|research)\s+)?(?:document|file|folder|spreadsheet|presentation|invoice|contract|acknowledgment|packet|materials?|[\w .-]+\.(?:docx?|xlsx?|pptx?|pdf))\s+"
    r"(?:(?:has been|was|is)\s+)?shared\s+(?:with|to)\s+you|"
    r"(?:you(?:'ve| have)?\s+(?:been invited|received an invitation)|invited\s+you)\s+to\s+(?:view|review|edit|access)|"
    r"new\s+(?:document|file|folder)\s+(?:share|invitation))\b",
    re.I | re.S,
)

_COMMON_SHARE_TYPOS = {
    "documant": "document",
    "documnet": "document",
    "shraed": "shared",
    "shaerd": "shared",
    "oepn": "open",
    "veiw": "view",
    "follder": "folder",
    "fodler": "folder",
    "spredsheet": "spreadsheet",
    "contrat": "contract",
    "acknolwedgment": "acknowledgment",
    "acknowlegment": "acknowledgment",
    "pakcet": "packet",
    "paktec": "packet",
}
_DOCUMENT_ACTION_RE = re.compile(
    r"\b(?:open|view|review|edit|access|download|read|sign)\b.{0,70}"
    r"\b(?:document|file|folder|spreadsheet|presentation|invoice|contract|share|invitation|packet|policy|acknowledgment|materials?|pdf|[\w.-]+\.(?:docx?|xlsx?|pptx?|pdf))\b"
    r"|\b(?:document|file|folder|spreadsheet|presentation|invoice|contract|share|invitation|packet|policy|acknowledgment|materials?|pdf|[\w.-]+\.(?:docx?|xlsx?|pptx?|pdf))\b.{0,70}"
    r"\b(?:open|view|review|edit|access|download|read|sign)\b",
    re.I | re.S,
)
_SHARED_REVIEW_ACTIVITY_RE = re.compile(
    r"\b(?:comments?|notes?|edits?|changes?)\b.{0,90}\b(?:ready|added|available|waiting|review|read|view)\b"
    r"|\b(?:read|view|review|open)\b.{0,90}\b(?:comments?|notes?|edits?|changes?)\b",
    re.I | re.S,
)
_SIGNIN_RE = re.compile(
    r"\b(?:(?:sign|log)\s*[- ]?in|authenticate|reauthenticate|verify\s+(?:your\s+)?(?:account|identity)|"
    r"enter\s+(?:your\s+)?(?:password|credentials?))\b",
    re.I,
)
_DOCUMENT_BRAND_RE = re.compile(
    r"\b(?:microsoft\s*(?:365|office|sharepoint|onedrive)|sharepoint|onedrive|google\s*(?:drive|docs)|"
    r"dropbox|docusign|adobe\s*(?:acrobat|document cloud)|box)\b",
    re.I,
)

_TRUSTED_DOCUMENT_HOSTS = (
    "sharepoint.com", "onedrive.com", "1drv.ms", "microsoft.com", "office.com",
    "office365.com", "google.com", "googleusercontent.com", "dropbox.com",
    "dropboxusercontent.com", "docusign.com", "adobe.com", "adobesign.com",
    "box.com",
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


def _is_trusted_document_host(host: str) -> bool:
    value = str(host or "").casefold().strip(".")
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_DOCUMENT_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_shared_document_rules(
    *,
    text: str,
    sender: str,
    urls,
    authentication_failures: int,
    risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Identify shared-document lures that lead to credential capture.

    A shared-document phrase alone is common legitimate mail. This rule requires
    a live document action and an untrusted destination, then requires a second
    credential-theft signal (sign-in instruction, failed authentication, risky
    URL, or an impersonated document-service brand). This multi-signal boundary
    avoids classifying normal Google Drive, OneDrive, Dropbox, DocuSign, Adobe,
    and Box notifications as phishing.
    """
    value = str(text or "")
    # Normalize a small, concept-level set of common transpositions seen in
    # real mail. This is intentionally limited to the three required concepts;
    # generic fuzzy matching would make ordinary business prose too permissive.
    for typo, canonical in _COMMON_SHARE_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [
        str(url) for url in (urls or [])
        if str(url or "").casefold().startswith(("http://", "https://"))
    ]
    shared_context = bool(_SHARED_DOCUMENT_RE.search(value))
    document_action = bool(
        _DOCUMENT_ACTION_RE.search(value)
        or (shared_context and _SHARED_REVIEW_ACTIVITY_RE.search(value))
    )
    if not http_urls or not shared_context or not document_action:
        return []

    untrusted_hosts = [host for host in map(_host, http_urls) if host and not _is_trusted_document_host(host)]
    if not untrusted_hosts:
        return []

    signin = bool(_SIGNIN_RE.search(value))
    brand_claim = bool(_DOCUMENT_BRAND_RE.search(value))
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    if not (signin or authentication_failures > 0 or risky_destination or brand_claim or free_mail_sender):
        return []

    return [SecurityRuleHit(
        rule_id="phishing.shared_document.credential_lure",
        points=78,
        reason="Shared-document invitation directs the recipient to an untrusted credential or sign-in destination",
        categories=("Phishing",),
        strong_flag="shared-document-credential-lure",
    )]
