from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_HR_CONTEXT_RE = re.compile(
    r"\b(?:hr|human resources|employee|staff|workforce|payroll|paystub|pay slip|payslip|"
    r"benefits?|compensation|leave|time off|tax form|w-?2|onboarding|performance review|"
    r"employee handbook|open enrollment)\b",
    re.I,
)
_PORTAL_RE = re.compile(
    r"\b(?:portal|self[- ]?service|dashboard|workspace|employee center|hr system|payroll system|"
    r"benefits center|workday|adp|bamboohr|successfactors|oracle hcm)\b",
    re.I,
)
_CREDENTIAL_ACTION_RE = re.compile(
    r"\b(?:sign|log)\s*[- ]?in\b"
    r"|\b(?:access|open|review|view|update|confirm|complete|enroll|download|acknowledge)\b.{0,90}"
    r"\b(?:portal|account|profile|payroll|paystub|payslip|benefits?|form|document|dashboard|record|details?)\b"
    r"|\b(?:portal|account|profile|payroll|paystub|payslip|benefits?|form|document|dashboard|record|details?)\b.{0,90}"
    r"\b(?:access|open|review|view|update|confirm|complete|enroll|download|acknowledge)\b",
    re.I | re.S,
)
_BRAND_RE = re.compile(
    r"\b(?:workday|adp|bamboohr|successfactors|oracle hcm|microsoft viva|ukg|paychex|gusto)\b",
    re.I,
)
_COMMON_TYPOS = {
    "employe": "employee", "empolyee": "employee", "payrol": "payroll",
    "benifits": "benefits", "benfits": "benefits", "protla": "portal",
    "protal": "portal", "singin": "signin", "sigin": "signin",
    "updat": "update", "oepn": "open",
}
_TRUSTED_HR_HOSTS = (
    "workday.com", "myworkday.com", "adp.com", "bamboohr.com", "successfactors.com",
    "oraclecloud.com", "ukg.com", "paychex.com", "gusto.com", "microsoft.com",
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
    return any(value == domain or value.endswith("." + domain) for domain in _TRUSTED_HR_HOSTS)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def evaluate_hr_portal_rules(
    *, text: str, sender: str, urls, authentication_failures: int, risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Detect HR-portal credential lures while preserving trusted HR links."""
    value = str(text or "")
    for typo, canonical in _COMMON_TYPOS.items():
        value = re.sub(rf"\b{re.escape(typo)}\b", canonical, value, flags=re.I)
    http_urls = [str(url) for url in (urls or []) if str(url or "").casefold().startswith(("http://", "https://"))]
    if not http_urls or not _HR_CONTEXT_RE.search(value) or not _PORTAL_RE.search(value) or not _CREDENTIAL_ACTION_RE.search(value):
        return []
    untrusted = [host for host in map(_host, http_urls) if host and not _trusted_host(host)]
    if not untrusted:
        return []
    free_mail_sender = _sender_domain(sender) in _CONSUMER_MAIL_DOMAINS
    brand_claim = bool(_BRAND_RE.search(value))
    if not (free_mail_sender or brand_claim or authentication_failures > 0 or risky_destination):
        return []
    return [SecurityRuleHit(
        rule_id="phishing.hr_portal.credential_lure",
        points=78,
        reason="HR or payroll portal notice directs the recipient to an untrusted employee-account destination",
        categories=("Phishing",),
        strong_flag="hr-portal-credential-lure",
    )]
