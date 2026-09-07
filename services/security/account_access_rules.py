from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from .models import SecurityRuleHit


_FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}

# Explicit anchors: stable attack concepts that are safe to recognize directly.
# They intentionally describe families of wording, not benchmark subjects/case text.
_PASSWORD_EXPIRY_RE = re.compile(
    r"\bpassword\b.{0,45}\b(?:expire[sd]?|expir(?:y|ation)|expiring)\b"
    r"|\b(?:expire[sd]?|expir(?:y|ation)|expiring)\b.{0,45}\bpassword\b",
    re.I | re.S,
)
_PASSWORD_CHANGE_ACTION_RE = re.compile(
    r"\b(?:change|update|renew|reset|confirm|verify)\b.{0,50}\bpassword\b"
    r"|\bpassword\b.{0,50}\b(?:change|update|renew|reset|confirm|verify)\b",
    re.I | re.S,
)
_SECURITY_ALERT_RE = re.compile(
    r"\b(?:security|account|sign[- ]?in|login|authentication)\b.{0,55}"
    r"\b(?:alert|warning|notice|anomal(?:y|ies)|unusual|suspicious|problem|issue|risk)\b"
    r"|\b(?:alert|warning|notice|anomal(?:y|ies)|unusual|suspicious)\b.{0,55}"
    r"\b(?:security|account|sign[- ]?in|login|authentication)\b",
    re.I | re.S,
)
_ACCOUNT_CONTEXT_RE = re.compile(
    r"\b(?:account|mailbox|email|work account|corporate account|company account|"
    r"microsoft 365|office 365|google workspace|password|session|security settings?|"
    r"authentication|authenticator|sign[- ]?in|login)\b",
    re.I,
)
_ACCESS_ACTION_RE = re.compile(
    # Verb form only. A noun such as "a sign-in was recorded" is context, not
    # an instruction. This distinction prevents authenticated alerts from being
    # escalated merely because they mention a past sign-in event.
    r"\b(?:mag[- ]?)?(?:sign|log)\s+in\b"
    r"|\b(?:authenticate|reauthenticate|re-authenticate)\b"
    r"|\b(?:verify|confirm|validate)\b.{0,45}\b(?:account|identity|mailbox|session|sign[- ]?in|login)\b"
    r"|\b(?:account|identity|mailbox|session|sign[- ]?in|login)\b.{0,45}\b(?:verify|confirm|validate)\b",
    re.I | re.S,
)

_CREDENTIAL_REQUEST_RE = re.compile(
    r"\b(?:send|provide|share|enter|submit|type|reply(?:\s+with)?|forward|disclose|confirm|verify|"
    r"ilagay|ibigay|ipadala|i[- ]?send|i[- ]?enter|ipasok|kumpirmahin)\b"
    r".{0,70}\b(?:password|credentials?|one[- ]time password|otp|security code|verification code|"
    r"recovery code|backup code|authentication code|auth code)\b"
    r"|\b(?:password|credentials?|one[- ]time password|otp|security code|verification code|"
    r"recovery code|backup code|authentication code|auth code)\b.{0,70}"
    r"\b(?:send|provide|share|enter|submit|type|reply|forward|disclose|confirm|verify|"
    r"ilagay|ibigay|ipadala|i[- ]?send|i[- ]?enter|ipasok|kumpirmahin)\b"
    r"|\b(?:sign|log)\s+in\b.{0,35}\b(?:with|using)\b.{0,25}"
    r"\b(?:your\s+)?(?:password|credentials?|otp|security code|verification code)\b",
    re.I | re.S,
)
_ACCOUNT_VERIFICATION_REQUEST_RE = re.compile(
    r"\b(?:verify|confirm|validate)\b.{0,45}\b(?:your\s+)?(?:account|identity|mailbox|session)\b"
    r"|\b(?:sign|log)\s+in\s+(?:here|now|to\s+(?:verify|confirm|validate))\b",
    re.I | re.S,
)
_PRESSURE_RE = re.compile(
    r"\b(?:urgent|urgently|immediate|immediately|right away|today|now|asap|final notice|"
    r"expires?|expiring|suspend(?:ed|sion)?|lock(?:ed)?|disable[sd]?|restricted|"
    r"interrupted|keep access|restore access|retain access|avoid suspension)\b",
    re.I,
)
_NEGATED_ACTION_PREFIX_RE = re.compile(
    r"\b(?:no|not|never|without|do not|don't|dont|no need to|should not|must not)\b.{0,28}$",
    re.I | re.S,
)
_NEGATED_ACTION_SUFFIX_RE = re.compile(
    r"^.{0,28}\b(?:is|are|was|were|will be|would be|should be)?\s*"
    r"(?:not|never)\s+(?:requested|required|needed|necessary|expected)\b",
    re.I | re.S,
)

_COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp",
    "co.nz", "com.sg", "com.ph", "com.br", "com.mx",
}


def _unnegated_search(pattern: re.Pattern, text: str) -> bool:
    value = str(text or "")
    for match in pattern.finditer(value):
        prefix = value[max(0, match.start() - 48):match.start()]
        # Keep negation local; a disclaimer elsewhere in the message should not
        # erase a separate live sign-in instruction.
        clause = re.split(r"[.!?;\n]", prefix)[-1]
        suffix = value[match.end():min(len(value), match.end() + 56)]
        if _NEGATED_ACTION_PREFIX_RE.search(clause):
            continue
        if _NEGATED_ACTION_SUFFIX_RE.search(suffix):
            continue
        return True
    return False


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _host(url: str) -> str:
    try:
        return (urlparse(str(url or "")).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _site_key(host: str) -> str:
    value = str(host or "").casefold().strip(".")
    if not value:
        return ""
    # Numeric hosts and single-label test hosts compare literally.
    if re.fullmatch(r"[0-9a-f:.]+", value, re.I) or "." not in value:
        return value
    labels = [part for part in value.split(".") if part]
    if len(labels) < 2:
        return value
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def _destination_mismatch(sender: str, urls) -> bool:
    sender_key = _site_key(_sender_domain(sender))
    if not sender_key:
        return False
    destination_keys = {
        _site_key(_host(url))
        for url in (urls or [])
        if str(url or "").casefold().startswith(("http://", "https://"))
    }
    destination_keys.discard("")
    return bool(destination_keys and any(key != sender_key for key in destination_keys))


def has_credential_request(text: str) -> bool:
    """Detect an actual credential/account-verification request, not mere topic mention."""
    value = str(text or "")
    return bool(
        _unnegated_search(_CREDENTIAL_REQUEST_RE, value)
        or _unnegated_search(_ACCOUNT_VERIFICATION_REQUEST_RE, value)
    )


def evaluate_account_access_rules(
    *,
    text: str,
    sender: str,
    urls,
    authentication_failures: int,
    strong_authentication: bool,
    risky_destination: bool = False,
) -> list[SecurityRuleHit]:
    """Evaluate explicit + compositional account-access phishing signals.

    Layer 1 uses explicit high-confidence attack anchors such as password-expiry
    pressure. Layer 2 composes broader concepts (account context + live sign-in
    action + destination/identity/pressure evidence). A weaker composition is
    deliberately Suspicious rather than forced to Phishing so contextual AI can
    refine it before genuinely NEW mail is published.
    """
    value = str(text or "")
    http_urls = [
        str(url)
        for url in (urls or [])
        if str(url or "").casefold().startswith(("http://", "https://"))
    ]
    if not http_urls:
        return []

    sender_domain = _sender_domain(sender)
    free_mail_sender = sender_domain in _FREE_MAIL_DOMAINS
    mismatch = _destination_mismatch(sender, http_urls)

    access_action = _unnegated_search(_ACCESS_ACTION_RE, value)
    account_context = bool(_ACCOUNT_CONTEXT_RE.search(value))
    password_expiry = bool(_PASSWORD_EXPIRY_RE.search(value))
    password_change = _unnegated_search(_PASSWORD_CHANGE_ACTION_RE, value)
    security_alert = bool(_SECURITY_ALERT_RE.search(value))
    pressure = bool(_PRESSURE_RE.search(value))

    hits: list[SecurityRuleHit] = []

    # Explicit anchor + concrete delivery/action evidence. Free-mail or failed
    # transport identity is enough to make a password-expiry/security-alert link
    # a high-confidence account-access lure.
    if (
        (password_expiry and (access_action or password_change))
        or (security_alert and access_action)
    ) and (authentication_failures > 0 or free_mail_sender or risky_destination):
        hits.append(SecurityRuleHit(
            rule_id="phishing.account_access.explicit_anchor",
            points=72,
            reason="Account-security/password lure directs the recipient to a live sign-in or password action",
            categories=("Phishing",),
            strong_flag="account-access-lure",
        ))
        return hits

    # General composition: no exact phrase is required. Combine the requested
    # action, account/authentication context, a live web destination, and at least
    # one independent risk modifier. Strong modifiers become Phishing; a mere
    # destination mismatch remains Suspicious and is eligible for AI refinement.
    if access_action and account_context:
        if authentication_failures > 0 or risky_destination:
            hits.append(SecurityRuleHit(
                rule_id="phishing.account_access.composite_strong",
                points=68,
                reason="Account sign-in action is combined with independent authentication or destination risk",
                categories=("Phishing",),
                strong_flag="account-access-lure",
            ))
        elif free_mail_sender and (pressure or password_expiry or security_alert):
            hits.append(SecurityRuleHit(
                rule_id="phishing.account_access.free_mail_pressure",
                points=64,
                reason="Free-mail sender combines account/security pressure with a live sign-in action",
                categories=("Phishing",),
                strong_flag="account-access-lure",
            ))
        elif mismatch and (pressure or password_expiry or security_alert or not strong_authentication):
            hits.append(SecurityRuleHit(
                rule_id="suspicious.account_access.destination_mismatch",
                points=40,
                reason="Account sign-in action points to a destination that does not align with the sender domain",
                categories=("Suspicious", "Phishing"),
            ))

    return hits
