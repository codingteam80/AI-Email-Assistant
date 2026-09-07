from __future__ import annotations

import base64
import html
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import parse_qsl, unquote, urlparse

from .models import SecurityRuleHit


_MAX_URLS = 32
_MAX_DECODE_DEPTH = 4
_TRUSTED_IDENTITY_HOSTS = (
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "sharepoint.com", "onedrive.com", "windows.net", "azure.com",
    "google.com", "okta.com", "duosecurity.com", "github.com",
    "apple.com", "icloud.com", "auth0.com",
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
}
_HIGH_RISK_TLDS = (
    ".invalid", ".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support",
)
_IDENTITY_PARAMETER_NAMES = {
    "email", "emailaddress", "loginhint", "login_hint", "mail", "recipient",
    "uid", "upn", "user", "username",
}
_REDIRECT_PARAMETER_NAMES = {
    "continue", "continueurl", "dest", "destination", "destinationurl", "goto",
    "link", "next", "nexturl", "out", "r", "redirect", "redirectto",
    "redirecturi", "redirect_uri", "redirecturl", "return", "returnto",
    "returnurl", "target", "u", "url",
}

_URL_RE = re.compile(r"https?://[^\s<>'\"\]\[()]+", re.I)
_SIGNIN_ACTION_RE = re.compile(
    r"\b(?:sign[ -]?in|log[ -]?in|authenticate|complete (?:the |your )?authentication|"
    r"continue\b.{0,70}\b(?:sign[ -]?in|authentication)|"
    r"access\b.{0,55}\b(?:account|mailbox|portal)|"
    r"open (?:the |your )?(?:account|mailbox|portal|document)|review (?:the |your )?account)\b",
    re.I,
)
_IDENTITY_CONTEXT_RE = re.compile(
    r"\b(?:microsoft\s*365|office\s*365|outlook|sharepoint|onedrive|google workspace|"
    r"google account|okta|single sign[- ]?on|sso|identity|account|mailbox|portal|"
    r"authentication|sign[ -]?in|log[ -]?in|session)\b",
    re.I,
)
_MFA_RE = re.compile(
    r"\b(?:mfa|2fa|multi[- ]?factor authentication|two[- ]?(?:factor|step) (?:authentication|"
    r"verification)|authenticator (?:app|prompt|notification)|push notification|"
    r"security[- ]?key|passkey|one[- ]?time (?:code|passcode)|otp|number matching)\b",
    re.I,
)
_RELAY_BEHAVIOR_RE = re.compile(
    r"\b(?:stay on|remain on|return to|come back to|keep)\b.{0,90}"
    r"\b(?:this |the )?(?:page|browser|tab|window|session)\b"
    r"|\b(?:do not|don't)\b.{0,45}\b(?:close|refresh|open (?:a |another )?new tab|"
    r"leave (?:the |this )?page)\b"
    r"|\b(?:browser|session|authentication|sign[ -]?in)\s*(?:handoff|relay|proxy|"
    r"synchroni[sz](?:e|ation)|continuation)\b"
    r"|\b(?:approve|complete|finish)\b.{0,90}\b(?:mfa|2fa|authenticator|push|passkey|"
    r"security key|number matching)\b.{0,90}\b(?:here|page|browser|tab|window|session)\b",
    re.I | re.S,
)
_KIT_MARKER_RE = re.compile(
    r"\b(?:adversary[ -]?in[ -]?the[ -]?middle|attacker[ -]?in[ -]?the[ -]?middle|aitm|"
    r"evilginx2?|modlishka|muraena|evilproxy|tycoon\s*2fa|tycoon2fa|sneaky\s*2fa|"
    r"sneaky2fa)\b",
    re.I,
)
_AUTH_PATH_RE = re.compile(
    r"/(?:auth|authenticate|authentication|login|signin|sign-in|sso|mfa|2fa|session|"
    r"oauth2?|saml|account)(?:[/_.?&#=-]|$)",
    re.I,
)
_BRAND_TOKENS = {
    "microsoft", "microsoft365", "office", "office365", "outlook", "sharepoint",
    "onedrive", "google", "googleworkspace", "okta", "duo", "github", "apple", "icloud",
}


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _domain_matches(left: str, right: str) -> bool:
    a = str(left or "").casefold().strip(".")
    b = str(right or "").casefold().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _host(url: str) -> str:
    try:
        return (urlparse(html.unescape(str(url or ""))).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _trusted_identity_host(host: str) -> bool:
    return any(_domain_matches(host, domain) for domain in _TRUSTED_IDENTITY_HOSTS)


def _unique(values) -> tuple[str, ...]:
    result = []
    seen = set()
    for raw in values:
        value = html.unescape(str(raw or "")).strip().rstrip(".,;)")
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _decode_base64_text(value: str) -> str:
    compact = re.sub(r"\s+", "", str(value or ""))
    if not 8 <= len(compact) <= 4096 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return ""
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(padded).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded:
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
    decoded_base64 = _decode_base64_text(current)
    if decoded_base64 and decoded_base64 not in variants:
        variants.append(decoded_base64)
    return tuple(variants)


def _expanded_urls(urls) -> tuple[str, ...]:
    queue = [(value, 0) for value in _unique(urls)[:_MAX_URLS]]
    found = []
    seen = set()
    while queue and len(found) < _MAX_URLS:
        raw, depth = queue.pop(0)
        for variant in _decoded_variants(raw):
            candidates = list(_URL_RE.findall(variant))
            if variant.casefold().startswith(("http://", "https://")):
                candidates.insert(0, variant)
            for candidate in _unique(candidates):
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
                normalized = re.sub(r"[^a-z0-9_]", "", str(name or "").casefold())
                decoded = unquote(str(parameter_value or ""))
                if (
                    normalized not in _REDIRECT_PARAMETER_NAMES
                    and not _URL_RE.search(decoded)
                    and "http" not in decoded.casefold()
                    and "http" not in _decode_base64_text(decoded).casefold()
                ):
                    continue
                for nested in _decoded_variants(parameter_value):
                    queue.append((nested, depth + 1))
    return _unique(found)


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


def _deceptive_brand_host(host: str) -> bool:
    if not host or _trusted_identity_host(host):
        return False
    normalized_labels = [re.sub(r"[^a-z0-9]", "", part) for part in host.split(".")]
    joined = "".join(normalized_labels)
    return any(token in normalized_labels or token in joined for token in _BRAND_TOKENS)


def _recipient_bound(url: str) -> bool:
    try:
        parsed = urlparse(html.unescape(str(url or "")))
        parameters = parse_qsl(parsed.query, keep_blank_values=True)
    except ValueError:
        return False
    for name, raw_value in parameters:
        normalized_name = re.sub(r"[^a-z0-9_]", "", str(name or "").casefold())
        value_variants = _decoded_variants(raw_value)
        combined = " ".join(value_variants)
        if normalized_name in _IDENTITY_PARAMETER_NAMES and str(raw_value or "").strip():
            return True
        if normalized_name == "state" and re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", combined, re.I):
            return True
    return False


def evaluate_aitm_phishing_rules(
    *, text: str, sender: str, urls, authentication_failures: int,
) -> list[SecurityRuleHit]:
    """Detect email-visible evidence of an AiTM authentication-proxy lure.

    This rule does not visit destinations. It requires an account sign-in action,
    an unrelated identity destination, and evidence of live MFA/session relay,
    recipient binding, brand deception, or a named AiTM kit.
    """
    value = str(text or "")
    expanded_urls = _expanded_urls(urls)
    if not expanded_urls:
        return []

    sender_domain = _sender_domain(sender)
    untrusted_urls = [
        url for url in expanded_urls
        if (host := _host(url))
        and not _trusted_identity_host(host)
        and not _domain_matches(host, sender_domain)
    ]
    if not untrusted_urls:
        return []

    sign_in_action = bool(_SIGNIN_ACTION_RE.search(value) and _IDENTITY_CONTEXT_RE.search(value))
    if not sign_in_action:
        return []

    url_text = "\n".join(untrusted_urls)
    mfa_flow = bool(_MFA_RE.search(value))
    relay_behavior = bool(_RELAY_BEHAVIOR_RE.search(value))
    kit_marker = bool(_KIT_MARKER_RE.search(value) or _KIT_MARKER_RE.search(url_text))
    recipient_bound = any(_recipient_bound(url) for url in untrusted_urls)
    branded_deception = any(_deceptive_brand_host(_host(url)) for url in untrusted_urls)
    risky_destination = any(_url_is_structurally_risky(url) for url in untrusted_urls)
    auth_destination = any(_AUTH_PATH_RE.search(urlparse(url).path or "") for url in untrusted_urls)
    sender_risk = authentication_failures > 0

    mechanism_evidence = bool(
        kit_marker
        or relay_behavior
        or (mfa_flow and recipient_bound)
        or (mfa_flow and branded_deception)
        or (mfa_flow and auth_destination and (risky_destination or sender_risk))
        or (recipient_bound and branded_deception and auth_destination)
    )
    if not mechanism_evidence:
        return []

    if kit_marker:
        reason = "Account sign-in lure exposes an AiTM phishing-kit or authentication-proxy marker"
    elif relay_behavior:
        reason = "Unrelated sign-in destination is paired with live MFA/browser-session relay instructions"
    elif recipient_bound:
        reason = "Unrelated sign-in destination binds the recipient identity into an MFA flow"
    elif branded_deception:
        reason = "Branded MFA sign-in is hosted on an unrelated look-alike identity destination"
    else:
        reason = "MFA sign-in lure directs to a structurally risky authentication destination"

    return [SecurityRuleHit(
        rule_id="phishing.aitm.authentication_proxy_lure",
        points=100,
        reason=reason,
        categories=("Phishing",),
        strong_flag="aitm-phishing-kit-lure",
    )]
