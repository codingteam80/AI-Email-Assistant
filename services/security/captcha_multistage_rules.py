from __future__ import annotations

import base64
import html
import ipaddress
import re
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import parse_qsl, unquote, urlparse

from .models import SecurityRuleHit


_MAX_URLS = 24
_MAX_DECODE_DEPTH = 4
_MAX_ATTACHMENT_SAMPLE = 262_144
_REDIRECT_PARAMETER_NAMES = {
    "continue", "continueurl", "dest", "destination", "destinationurl", "goto",
    "link", "next", "nexturl", "out", "r", "redirect", "redirectto",
    "redirecturi", "redirecturl", "return", "returnto", "returnurl", "target", "u", "url",
}
_CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
}
_TRUSTED_NAVIGATION_HOSTS = (
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "google.com", "googleusercontent.com", "github.com", "okta.com",
    "duosecurity.com", "cloudflare.com", "dropbox.com", "adobe.com",
    "docusign.com", "zoom.us", "slack.com", "salesforce.com",
)
_HIGH_RISK_TLDS = (
    ".invalid", ".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support",
)

_URL_RE = re.compile(r"https?://[^\s<>'\"\]\[()]+", re.I)
_CAPTCHA_RE = re.compile(
    r"\b(?:captcha|re[- ]?captcha|hcaptcha|turnstile|cloudflare challenge|"
    r"human verification|human check|prove (?:that )?you(?:'re| are) human|"
    r"verify (?:that )?you(?:'re| are) human|i(?:'m| am) not a robot|not a robot|"
    r"bot check|anti[- ]?bot|security challenge|browser challenge|challenge page)\b",
    re.I,
)
_CAPTCHA_URL_RE = re.compile(
    r"(?:^|[/_.?&=-])(?:captcha|recaptcha|hcaptcha|turnstile|human[-_]?check|"
    r"human[-_]?verification|bot[-_]?check|security[-_]?challenge)(?:$|[/_.?&=-])",
    re.I,
)
_STAGE_RE = re.compile(
    r"\b(?:first (?:complete|finish|pass)|after (?:the |this )?(?:check|challenge|captcha)|"
    r"once (?:the |this )?(?:check|challenge|captcha) is complete|then (?:continue|proceed|"
    r"open|sign[ -]?in)|continue to (?:the )?next step|next step|intermediate page|"
    r"redirect(?:ed|ion)?|forward(?:ed)? to|opens? a second page|two[- ]?step link|"
    r"multi[- ]?stage)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:complete|continue|proceed|open|view|review|read|download|listen|play|"
    r"sign[ -]?in|log[ -]?in|access|restore|retain|keep|confirm|approve|authorize|"
    r"grant|accept|renew|unlock|release|reconnect|acknowledge|submit)\b",
    re.I,
)
_SENSITIVE_CONTEXT_RE = re.compile(
    r"\b(?:account|mailbox|email|microsoft\s*365|office\s*365|google workspace|"
    r"sharepoint|onedrive|document|file|invoice|statement|payroll|benefits?|hr portal|"
    r"password|credential|identity|session|sign[ -]?in|log[ -]?in|security alert|"
    r"mfa|2fa|authentication|permission|oauth|voicemail|voice message|storage|quota|"
    r"payment|bank|remittance|delivery)\b",
    re.I,
)
_CREDENTIAL_RE = re.compile(
    r"\b(?:enter|provide|submit|use|type)\b.{0,80}"
    r"\b(?:password|credentials?|passcode|one[- ]?time code|otp|mfa code|2fa code|"
    r"recovery code|authentication code|security code)\b",
    re.I | re.S,
)
_TEXT_ATTACHMENT_TYPES = {"text/html", "image/svg+xml"}


@dataclass(frozen=True)
class _LinkEvidence:
    all_urls: tuple[str, ...]
    host_chains: tuple[tuple[str, ...], ...]
    attachment_text: str


def _unique(values) -> tuple[str, ...]:
    result = []
    seen = set()
    for value in values:
        item = html.unescape(str(value or "")).strip().rstrip(".,;)")
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return tuple(result)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _host(value: str) -> str:
    try:
        return (urlparse(str(value or "")).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _domain_matches(left: str, right: str) -> bool:
    a = str(left or "").casefold().strip(".")
    b = str(right or "").casefold().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _trusted_navigation_host(value: str) -> bool:
    host = str(value or "").casefold().strip(".")
    return any(_domain_matches(host, domain) for domain in _TRUSTED_NAVIGATION_HOSTS)


def _decode_base64_url(value: str) -> str:
    compact = re.sub(r"\s+", "", str(value or ""))
    if not 16 <= len(compact) <= 4096 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return ""
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(padded).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if "http://" in decoded.casefold() or "https://" in decoded.casefold():
            return decoded
    return ""


def _decoded_variants(value: str) -> tuple[str, ...]:
    variants = []
    current = html.unescape(str(value or "")).replace("\\/", "/")
    for _ in range(_MAX_DECODE_DEPTH):
        if current not in variants:
            variants.append(current)
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    base64_value = _decode_base64_url(current)
    if base64_value and base64_value not in variants:
        variants.append(base64_value)
    return tuple(variants)


def _nested_urls(url: str) -> tuple[str, ...]:
    root = html.unescape(str(url or "")).strip()
    if not root:
        return ()
    queue = [(root, 0)]
    found = []
    seen = set()
    while queue and len(found) < _MAX_URLS:
        current, depth = queue.pop(0)
        for variant in _decoded_variants(current):
            for candidate in _URL_RE.findall(variant):
                candidate = candidate.rstrip(".,;)")
                if candidate in seen:
                    continue
                seen.add(candidate)
                found.append(candidate)
                if depth < _MAX_DECODE_DEPTH:
                    queue.append((candidate, depth + 1))
            if depth >= _MAX_DECODE_DEPTH:
                continue
            try:
                parsed = urlparse(variant)
                parameters = parse_qsl(parsed.query, keep_blank_values=True)
                if parsed.fragment:
                    parameters.append(("fragment", parsed.fragment))
            except ValueError:
                parameters = []
            for name, parameter_value in parameters:
                normalized_name = re.sub(r"[^a-z0-9]", "", str(name or "").casefold())
                decoded_parameter = unquote(str(parameter_value or ""))
                if (
                    normalized_name not in _REDIRECT_PARAMETER_NAMES
                    and not _URL_RE.search(decoded_parameter)
                    and not _decode_base64_url(decoded_parameter)
                ):
                    continue
                for decoded in _decoded_variants(parameter_value):
                    queue.append((decoded, depth + 1))
    if root.casefold().startswith(("http://", "https://")) and root not in seen:
        found.insert(0, root)
    return _unique(found)


def _attachment_sample(attachment: dict) -> str:
    filename = str(attachment.get("filename") or "").casefold()
    content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
    if content_type not in _TEXT_ATTACHMENT_TYPES and not filename.endswith((".html", ".htm", ".svg")):
        return ""
    data = attachment.get("data")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data[:_MAX_ATTACHMENT_SAMPLE]).decode("utf-8", errors="ignore")
    if isinstance(data, str):
        return data[:_MAX_ATTACHMENT_SAMPLE]
    return ""


def _collect_link_evidence(urls, attachments) -> _LinkEvidence:
    attachment_samples = [
        sample for attachment in (attachments or [])
        if (sample := _attachment_sample(attachment))
    ]
    attachment_text = "\n".join(attachment_samples)
    seeds = list(urls or [])
    seeds.extend(_URL_RE.findall(html.unescape(attachment_text).replace("\\/", "/")))

    all_urls = []
    chains = []
    for seed in _unique(seeds)[:_MAX_URLS]:
        expanded = _nested_urls(seed)
        all_urls.extend(expanded)
        hosts = _unique(_host(value) for value in expanded if _host(value))
        if hosts:
            chains.append(hosts)
    return _LinkEvidence(
        all_urls=_unique(all_urls),
        host_chains=tuple(chains),
        attachment_text=attachment_text,
    )


def _url_is_structurally_risky(url: str) -> bool:
    try:
        parsed = urlparse(html.unescape(str(url or "")))
    except ValueError:
        return True
    host = (parsed.hostname or "").casefold().strip(".")
    if not host:
        return False
    if parsed.username or parsed.password:
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    return bool(
        host.startswith("xn--")
        or ".xn--" in host
        or host in _SHORTENERS
        or host.endswith(_HIGH_RISK_TLDS)
    )


def evaluate_captcha_multistage_rules(
    *, text: str, sender: str, urls, body_html: str, attachments,
    authentication_failures: int,
) -> list[SecurityRuleHit]:
    """Detect CAPTCHA-gated and chained-link phishing without visiting URLs."""
    evidence = _collect_link_evidence(urls, attachments)
    if not evidence.all_urls:
        return []

    visible_attachment_text = re.sub(r"(?s)<[^>]+>", " ", evidence.attachment_text)
    combined = "\n".join((str(text or ""), visible_attachment_text))
    captcha_gate = bool(
        _CAPTCHA_RE.search(combined)
        or any(_CAPTCHA_URL_RE.search(value) for value in evidence.all_urls)
    )
    stage_language = bool(_STAGE_RE.search(combined))
    credential_request = bool(_CREDENTIAL_RE.search(combined))
    lure_context = bool(
        credential_request
        or (_ACTION_RE.search(combined) and _SENSITIVE_CONTEXT_RE.search(combined))
    )
    if not lure_context or not (captcha_gate or stage_language):
        return []

    cross_domain_chains = [chain for chain in evidence.host_chains if len(chain) >= 2]
    all_hosts = _unique(_host(value) for value in evidence.all_urls if _host(value))
    multiple_unrelated_hosts = len(all_hosts) >= 2
    risky_urls = [value for value in evidence.all_urls if _url_is_structurally_risky(value)]
    sender_domain = _sender_domain(sender)
    untrusted_destinations = [
        value for value in evidence.all_urls
        if _host(value)
        and not _domain_matches(_host(value), sender_domain)
        and not _trusted_navigation_host(_host(value))
    ]
    sender_risk = bool(authentication_failures > 0 or sender_domain in _CONSUMER_MAIL_DOMAINS)

    if captcha_gate and risky_urls:
        reason = "CAPTCHA-gated account or document lure leads to a structurally risky destination"
    elif captcha_gate and credential_request and untrusted_destinations:
        reason = "CAPTCHA-gated link is paired with a credential request on an unrelated destination"
    elif captcha_gate and cross_domain_chains and sender_risk and untrusted_destinations:
        reason = "CAPTCHA-gated lure conceals a cross-domain redirect chain"
    elif stage_language and cross_domain_chains and (risky_urls or sender_risk):
        reason = "Sensitive-action lure uses a staged cross-domain redirect chain"
    elif stage_language and multiple_unrelated_hosts and risky_urls:
        reason = "Sensitive-action lure directs the recipient through multiple unrelated stages"
    else:
        return []

    return [SecurityRuleHit(
        rule_id="phishing.captcha_multistage.gated_redirect_lure",
        points=100,
        reason=reason,
        categories=("Phishing",),
        strong_flag="captcha-multistage-phishing-lure",
    )]
