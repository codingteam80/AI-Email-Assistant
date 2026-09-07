from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}
_TRUSTED_DEVICE_FLOW_SENDERS = (
    "microsoft.com", "accountprotection.microsoft.com", "github.com", "google.com",
)
_DEVICE_LOGIN_HOSTS = (
    "microsoft.com", "microsoftonline.com", "aka.ms", "github.com", "google.com",
)

_DEVICE_FLOW_RE = re.compile(
    r"\b(?:device[- ]?code|device authorization|device authentication|device login|"
    r"device sign[- ]?in|device pairing|pairing code|user code|authorization code|"
    r"cross[- ]?device sign[- ]?in|limited[- ]?input device)\b",
    re.I,
)
_DEVICE_CODE_ACTION_RE = re.compile(
    r"\b(?:enter|paste|input|type|use|submit|copy)\b.{0,90}"
    r"\b(?:device[- ]?code|user code|pairing code|authorization code|meeting id|code shown|code below|code)\b"
    r"|\b(?:device[- ]?code|user code|pairing code|authorization code|meeting id|code shown|code below)\b"
    r".{0,90}\b(?:enter|paste|input|type|use|submit|copy)\b",
    re.I | re.S,
)
_CODE_VALUE_RE = re.compile(
    r"\b(?:device[- ]?code|user code|pairing code|authorization code|meeting code|meeting id|code)"
    r"\s*(?::|is|=|-)?\s*([A-Z0-9]{6,10}|[A-Z0-9]{3,5}(?:[- ][A-Z0-9]{3,5}){1,2})\b",
    re.I,
)
_DEVICE_LOGIN_PATH_RE = re.compile(
    r"/(?:devicelogin|deviceauth|devicecode|activate|pair)(?:[/?.#]|$)",
    re.I,
)
_DEVICE_LURE_RE = re.compile(
    r"\b(?:meeting invitation|meeting invite|teams meeting|join (?:the |this )?(?:meeting|"
    r"call|event|webinar)|webinar invitation|event invitation|organizer|speaker|guest access|"
    r"shared briefing|conference access|remote session|support session)\b",
    re.I,
)
_DEVICE_PRESSURE_RE = re.compile(
    r"\b(?:valid for|expires? in|within)\s+(?:the next\s+)?(?:5|10|15|20|30)\s+minutes?\b"
    r"|\b(?:complete now|use immediately|before it expires|time[- ]?limited code)\b",
    re.I,
)
_CLIPBOARD_RE = re.compile(
    r"\b(?:copied|placed|saved|written)\b.{0,70}\bclipboard\b"
    r"|\bclipboard\b.{0,70}\b(?:paste|code)\b",
    re.I | re.S,
)
_ATTACKER_SESSION_RE = re.compile(
    r"\b(?:authenticate|authorize|approve|confirm|complete|continue|sign[ -]?in|log[ -]?in)\b"
    r".{0,120}\b(?:session|request|device|meeting|application|app|connection)\b",
    re.I | re.S,
)
_USER_INITIATED_RE = re.compile(
    r"\b(?:you requested|requested by you|your requested setup|the device you are setting up|"
    r"your new (?:tv|console|printer|device)|you started this sign[- ]?in|"
    r"you initiated this request|command you just ran|your cli sign[- ]?in)\b",
    re.I,
)
_SAFETY_NOTICE_RE = re.compile(
    r"\b(?:if you did not (?:request|start|initiate)|do not enter this code for anyone|"
    r"never share (?:this |a )?code|cancel (?:the |this )?request|deny (?:the |this )?request)\b",
    re.I,
)

_EXFIL_ACTION_RE = re.compile(
    r"\b(?:send|share|upload|export|copy|paste|provide|forward|attach|transfer|submit|"
    r"extract|collect|package|zip)\b",
    re.I,
)
_SESSION_SECRET_RE = re.compile(
    r"\b(?:session cookies?|authentication cookies?|auth cookies?|browser cookies?|"
    r"session tokens?|access tokens?|refresh tokens?|bearer tokens?|id tokens?|jwt tokens?|"
    r"browser sessions?|authenticated sessions?|cookie database|cookies\.sqlite|"
    r"localstorage tokens?|sessionstorage tokens?|authorization headers?)\b",
    re.I,
)
_DEVTOOLS_RE = re.compile(
    r"\b(?:developer tools|devtools|inspect element|application tab|storage tab|"
    r"localstorage|sessionstorage|network tab)\b",
    re.I,
)
_COOKIE_VALUE_RE = re.compile(
    r"\b(?:copy|send|paste|export|provide|upload)\b.{0,120}"
    r"\b(?:cookie value|session value|token value|authorization header|bearer value)\b",
    re.I | re.S,
)
_HAR_RE = re.compile(r"\b(?:har|http archive|network trace)\b", re.I)
_HAR_SENSITIVE_RE = re.compile(
    r"\b(?:include|preserve|retain|do not sanitize|don't sanitize|without sanitizing|"
    r"unredacted|with sensitive data|keep)\b.{0,100}"
    r"\b(?:cookies?|tokens?|authorization headers?|credentials?|session data)\b",
    re.I | re.S,
)
_SESSION_TRANSFER_RE = re.compile(
    r"\b(?:bypass|skip|avoid)\b.{0,80}\b(?:mfa|2fa|authentication|sign[- ]?in|log[- ]?in)\b"
    r"|\b(?:keep|preserve|clone|migrate|transfer|restore|reuse|replay)\b.{0,90}"
    r"\b(?:logged[- ]?in session|authenticated session|browser session|session cookie|token)\b",
    re.I | re.S,
)
_TOKEN_EXTRACTION_RE = re.compile(
    r"\b(?:localstorage|sessionstorage|application tab|storage tab|network tab)\b"
    r".{0,160}\b(?:access token|refresh token|bearer token|jwt|cookie|authorization)\b",
    re.I | re.S,
)
_SANITIZED_SUPPORT_RE = re.compile(
    r"\b(?:saniti[sz]ed|redacted|remove|exclude|without)\b.{0,80}"
    r"\b(?:cookies?|tokens?|authorization headers?|credentials?|sensitive data)\b",
    re.I | re.S,
)
def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _domain_matches(left: str, right: str) -> bool:
    a = str(left or "").casefold().strip(".")
    b = str(right or "").casefold().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _trusted_device_sender(sender_domain: str) -> bool:
    return any(_domain_matches(sender_domain, domain) for domain in _TRUSTED_DEVICE_FLOW_SENDERS)


def _device_login_urls(urls) -> list[str]:
    matches = []
    for raw in urls or []:
        value = str(raw or "")
        try:
            parsed = urlparse(value)
        except ValueError:
            continue
        host = (parsed.hostname or "").casefold().strip(".")
        if not host or not _DEVICE_LOGIN_PATH_RE.search(parsed.path or ""):
            continue
        if any(_domain_matches(host, domain) for domain in _DEVICE_LOGIN_HOSTS):
            matches.append(value)
    return matches


def _has_live_code_value(text: str) -> bool:
    for match in _CODE_VALUE_RE.finditer(str(text or "")):
        compact = re.sub(r"[- ]", "", str(match.group(1) or ""))
        if (
            6 <= len(compact) <= 12
            and compact.isalnum()
            and any(ch.isalpha() for ch in compact)
            and any(ch.isdigit() for ch in compact)
        ):
            return True
    return False


def _positive_exfil_action(text: str) -> bool:
    for match in _EXFIL_ACTION_RE.finditer(str(text or "")):
        prefix = str(text or "")[max(0, match.start() - 50):match.start()]
        if re.search(r"\b(?:do not|don't|never|must not|should not)\b[^.!?;]{0,35}$", prefix, re.I):
            continue
        return True
    return False


def evaluate_device_code_session_rules(
    *, text: str, sender: str, urls, authentication_failures: int,
) -> list[SecurityRuleHit]:
    """Detect device-code authorization and token/session-exfiltration lures."""
    value = str(text or "")
    sender_domain = _sender_domain(sender)
    free_mail_sender = sender_domain in _CONSUMER_MAIL_DOMAINS
    device_urls = _device_login_urls(urls)

    device_flow = bool(_DEVICE_FLOW_RE.search(value) or device_urls)
    device_action = bool(_DEVICE_CODE_ACTION_RE.search(value))
    code_value = _has_live_code_value(value)
    meeting_lure = bool(_DEVICE_LURE_RE.search(value))
    pressure = bool(_DEVICE_PRESSURE_RE.search(value))
    clipboard = bool(_CLIPBOARD_RE.search(value))
    attacker_session_action = bool(_ATTACKER_SESSION_RE.search(value))
    initiated = bool(_USER_INITIATED_RE.search(value))
    safety_notice = bool(_SAFETY_NOTICE_RE.search(value))

    legitimate_initiated_flow = bool(
        initiated
        and safety_notice
        and authentication_failures <= 0
        and _trusted_device_sender(sender_domain)
        and not (meeting_lure or pressure or clipboard)
    )
    device_risk = bool(
        authentication_failures > 0
        or free_mail_sender
        or meeting_lure
        or pressure
        or clipboard
    )
    if (
        device_flow
        and device_action
        and (code_value or device_urls)
        and attacker_session_action
        and device_risk
        and not legitimate_initiated_flow
    ):
        return [SecurityRuleHit(
            rule_id="phishing.device_code.authorization_lure",
            points=100,
            reason="Device-code instruction can authorize an attacker-controlled session",
            categories=("Phishing",),
            strong_flag="device-code-session-theft-lure",
        )]

    session_secret = bool(_SESSION_SECRET_RE.search(value))
    positive_exfil = _positive_exfil_action(value)
    cookie_value = bool(_COOKIE_VALUE_RE.search(value))
    developer_extraction = bool(_DEVTOOLS_RE.search(value) and _TOKEN_EXTRACTION_RE.search(value))
    sensitive_har = bool(_HAR_RE.search(value) and _HAR_SENSITIVE_RE.search(value))
    session_transfer = bool(_SESSION_TRANSFER_RE.search(value))
    sanitized_support = bool(
        _HAR_RE.search(value)
        and _SANITIZED_SUPPORT_RE.search(value)
        and not _HAR_SENSITIVE_RE.search(value)
    )

    if (
        session_secret
        and positive_exfil
        and not sanitized_support
        and (cookie_value or developer_extraction or sensitive_har or session_transfer)
    ):
        return [SecurityRuleHit(
            rule_id="phishing.session_token.exfiltration_lure",
            points=100,
            reason="Requests export or transfer of authentication tokens or an active browser session",
            categories=("Phishing",),
            strong_flag="device-code-session-theft-lure",
        )]

    return []
