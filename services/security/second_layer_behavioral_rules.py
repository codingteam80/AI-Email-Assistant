"""Provider-independent behavioral floors for ambiguous second-layer threats.

These rules deliberately avoid benchmark subjects and sender allow/deny lists.  They
cover combinations that a provider adapter can observe in ordinary RFC mail while
leaving history-dependent claims (reputation, consent, thread existence) to metadata.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from email.utils import parseaddr
from urllib.parse import urlparse

from services.security.models import SecurityRuleHit


_FREE_MAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
    "icloud.com", "mail.com", "proton.me", "protonmail.com",
}


def _hit(rule_id: str, category: str, flag: str, reason: str) -> SecurityRuleHit:
    return SecurityRuleHit(
        rule_id=rule_id,
        points=100,
        reason=reason,
        categories=(category,),
        strong_flag=flag,
    )


def _truthy(value: object) -> bool:
    return value is True or value == 1 or str(value or "").casefold() in {"true", "yes", "high", "low", "poor"}


def _urls(email_data: Mapping, text: str) -> list[str]:
    values: list[str] = []
    for item in email_data.get("links") or ():
        if isinstance(item, Mapping):
            value = item.get("url") or item.get("href") or item.get("target")
        else:
            value = item
        if value:
            values.append(str(value))
    values.extend(re.findall(r"https?://[^\s<>\]\[\"']+", text, re.I))
    return list(dict.fromkeys(values))


def _external_link(email_data: Mapping, text: str) -> bool:
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1]
    sender_domain = sender.rpartition("@")[2].casefold().strip(".")
    for value in _urls(email_data, text):
        try:
            host = (urlparse(value).hostname or "").casefold().strip(".")
        except Exception:
            host = ""
        if host and (not sender_domain or (host != sender_domain and not host.endswith("." + sender_domain))):
            return True
    return False


def _risky_external_link(email_data: Mapping, text: str) -> bool:
    """Require destination risk, not merely a cross-domain documentation link."""
    evidence = " ".join(str(email_data.get(k) or "") for k in (
        "spam_evidence", "authentication_results", "link_reputation", "security_analysis"
    ))
    if re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|\b(?:low|poor|bad|risky|suspicious|untrusted)\s+reputation\b", evidence, re.I):
        return _external_link(email_data, text)
    for item in email_data.get("links") or ():
        if isinstance(item, Mapping) and any(_truthy(item.get(k)) for k in (
            "suspicious", "is_suspicious", "untrusted", "destination_mismatch"
        )):
            return True
    for value in _urls(email_data, text):
        try:
            host = (urlparse(value).hostname or "").casefold().strip(".")
        except Exception:
            host = ""
        if host.endswith(".invalid") or host == "invalid":
            return True
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1]
    return sender.rpartition("@")[2].casefold() in _FREE_MAIL and _external_link(email_data, text)


def _identity_impersonation_reason(email_data: Mapping, text: str) -> str:
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1]
    sender_domain = sender.rpartition("@")[2].casefold()
    claimed_role = re.search(
        r"\b(?:i am|i'm|i represent|we represent|this is|we are|writing (?:from|on behalf of)|from)\b.{0,80}"
        r"\b(?:ceo|chief executive|executive|finance|accounts? payable|procurement|hr|human resources|"
        r"help ?desk|administrator|support|legal|law firm|bank security|delivery company|courier|"
        r"vendor|supplier|business partner|microsoft support)\b",
        text,
        re.I | re.S,
    )
    alternate_channel = re.search(
        r"\b(?:temporary|personal|alternate|backup|private|new)\s+"
        r"(?:email|address|mailbox|account)|official (?:email|mailbox)\b.{0,35}\b(?:unavailable|down)|"
        r"using (?:my|this) personal (?:email|account)|reply (?:only )?(?:to|here)|"
        r"different (?:email|address|mailbox)",
        text,
        re.I | re.S,
    )
    requested_action = re.search(
        r"\b(?:reply|respond|confirm|verify|send|share|provide|wire|transfer|redirect|change|update|"
        r"keep|do not tell|don't tell)\b",
        text,
        re.I,
    )
    organizational_identity = re.search(
        r"\b(?:ceo|executive|finance|accounts? payable|procurement|hr|human resources|help ?desk|"
        r"administrator|microsoft|bank|legal|law firm|vendor|supplier|delivery company|courier)\b",
        text,
        re.I,
    )
    auth_failure = re.search(
        r"\b(?:spf|dkim|dmarc)\s*=\s*fail\b|\b(?:spoof|lookalike|typosquat|homograph)\b",
        " ".join(str(email_data.get(k) or "") for k in (
            "spam_evidence", "authentication_results", "security_analysis"
        )),
        re.I,
    )
    if claimed_role and alternate_channel and requested_action and (
        sender_domain in _FREE_MAIL or auth_failure
    ):
        return "An organizational identity claim requests action through an unrelated alternate or consumer mailbox"
    if organizational_identity and requested_action and auth_failure:
        return "An organizational identity requests action while sender authentication or domain identity is anomalous"
    return ""


def _scam_reason(text: str) -> str:
    recovery = re.search(r"\b(?:recover|recovery|retrieve|refund|reimburse)\b.{0,90}\b(?:lost|stolen|money|funds?|loss|reimbursement)\b", text, re.I | re.S)
    prerequisite_fee = re.search(
        r"\b(?:after|once|before|so (?:that )?|in order to)\b.{0,100}\b(?:pay|payment|fee|charge|deposit)\b"
        r"|\b(?:pay|send|transfer)\b.{0,100}\b(?:fee|charge|deposit)\b.{0,100}\b(?:recover|refund|reimburse|release|receive)\b",
        text,
        re.I | re.S,
    )
    inheritance = re.search(r"\b(?:inheritance|estate|beneficiary|bequest)\b", text, re.I)
    legal_fee = re.search(r"\b(?:legal|clearance|release|processing|transfer|inheritance)\s+(?:fee|charge)\b", text, re.I)
    parcel_fee = re.search(
        r"\b(?:parcel|package|shipment)\b.{0,100}\b(?:insurance|shipping|release|customs)\s+(?:fee|charge)\b"
        r"|\b(?:insurance|shipping|release|customs)\s+(?:fee|charge)\b.{0,100}\b(?:parcel|package|shipment)\b",
        text,
        re.I | re.S,
    )
    release = re.search(r"\b(?:before|after|once|to|so (?:that )?)\b.{0,100}\b(?:release|deliver|receive|reimburse|recover)\b", text, re.I | re.S)
    if recovery and prerequisite_fee:
        return "Recovery or reimbursement is conditioned on an advance payment"
    if inheritance and legal_fee and re.search(r"\b(?:send|pay|transfer|wire)\b", text, re.I):
        return "An unexpected inheritance or beneficiary claim requires a legal or clearance fee"
    if parcel_fee and release and re.search(r"\b(?:send|pay|transfer|wire)\b", text, re.I):
        return "A parcel release is conditioned on an advance shipping or insurance charge"
    return ""


def _phishing_reason(email_data: Mapping, text: str) -> str:
    external = _risky_external_link(email_data, text)
    credential = re.search(
        r"\b(?:enter|provide|submit|confirm|validate|verify|authenticate|use)\b.{0,90}"
        r"\b(?:login|log-in|sign-in|account|user(?:name)?|password|credentials?|login details?|sign-in details?)\b",
        text,
        re.I | re.S,
    )
    protected_message = re.search(
        r"\b(?:protected|secure|encrypted|confidential)\s+(?:message|document|mail)\b.{0,120}"
        r"\b(?:authenticate|sign in|log in|verify)\b|\b(?:authenticate|sign in|log in|verify)\b.{0,120}"
        r"\b(?:read|view|open|access)\b.{0,50}\b(?:message|document|mail)\b",
        text,
        re.I | re.S,
    )
    if external and credential:
        return "An external destination requests login or sign-in details"
    if external and protected_message:
        return "An external destination requires authentication to read a protected message"
    return ""


def _spam_reason(email_data: Mapping, text: str) -> tuple[str, str]:
    commercial = re.search(r"\b(?:offer|advertis|sale|buy|service|product|catalog|discount|promotion)\w*\b", text, re.I)
    if commercial and re.search(r"\b(?:found|obtained|collected|scraped|harvested)\b.{0,75}\b(?:email|address|contact)\b.{0,75}\b(?:online|public (?:directory|website|source))\b", text, re.I | re.S):
        return "harvested-address-spam", "Commercial outreach says the recipient address was collected from a public source"
    if commercial and re.search(r"\b(?:purchased|bought|rented|acquired)\b.{0,60}\b(?:contact|address|mailing|email)\s+list\b", text, re.I | re.S):
        return "bulk-list-spam", "Commercial mail was sent through a purchased or rented contact list"
    if commercial and re.search(r"\b(?:did not|didn't|never|no)\b.{0,60}\b(?:request|subscribe|sign up|opt in|permission)\b", text, re.I | re.S):
        return "unwanted-one-off-spam", "Commercial outreach acknowledges there was no request, subscription, or consent"
    if commercial and re.search(r"\b(?:reply-style|fake reply|false reply|no earlier (?:message|request|thread)|not (?:a |an )?(?:real|existing) (?:reply|thread))\b", text, re.I):
        return "deceptive-subject-spam", "Commercial outreach uses a reply-style presentation without an existing conversation"
    subscription_burst = any(_truthy(email_data.get(k)) for k in (
        "subscription_bombing_detected", "email_bombing_detected", "mailbox_burst_detected"
    )) or bool(re.search(r"\b(?:burst|flood|dozens|hundreds|many)\b.{0,80}\b(?:subscription|confirmation|newsletter|signup)\w*\b", text, re.I | re.S))
    if subscription_burst:
        return "email-subscription-bombing-spam", "A burst of unwanted subscription confirmations indicates subscription bombing"

    # Catch deliberately split/obfuscated advertising while preserving the
    # obfuscation itself as required evidence.
    normalized = unicodedata.normalize("NFKC", text)
    spaced = bool(re.search(r"(?<!\w)(?:[a-z0-9][ ._*~-]+){3,}[a-z0-9](?!\w)", normalized, re.I))
    collapsed = re.sub(r"(?<=[A-Za-z])[ ._*~-]+(?=[A-Za-z])", "", normalized).casefold()
    if spaced and re.search(r"(?:limitedoffer|buynow|specialoffer|freegift|ordernow|shopnow)", collapsed):
        return "obfuscated-content-spam", "Advertising words are deliberately separated to evade content filters"
    return "", ""


def _suspicious_reason(email_data: Mapping, text: str) -> tuple[str, str]:
    checks = (
        ("unexpected-contact-email", r"\b(?:unexpected|unknown|unfamiliar|new)\s+(?:contact|sender)\b|\bno prior (?:contact|conversation|history|context)\b", "The sender or contact is explicitly unexpected and has no prior context"),
        ("context-mismatch-email", r"\b(?:topic|request|message|content)\b.{0,65}\b(?:does not|doesn't|did not|unrelated|mismatch)\b.{0,65}\b(?:thread|conversation|subject|context|topic)|\bunrelated request\b", "The request is explicitly unrelated to the thread or conversation"),
        ("sender-anomaly-email", r"\b(?:different|changed|new|unexpected) sender (?:address|mailbox|domain)|\bsender address\b.{0,65}\b(?:different|changed|unusual|unexpected)\b", "The message reports a sender address different from the established pattern"),
        ("authentication-anomaly-email", r"\b(?:authentication|spf|dkim|dmarc)\b.{0,85}\b(?:changed|different|failed|fail|anomal|unusual|unexpected)\b|\bauth(?:entication)? result\b.{0,65}\busual pattern\b", "The message reports authentication results that differ from the normal pattern"),
        ("header-inconsistency-email", r"\bfrom\b.{0,45}\breply[- ]?to\b.{0,55}\b(?:mismatch|different|differs|does not match|doesn't match|inconsistent)\b|\b(?:mismatch|different|inconsistent)\b.{0,55}\bfrom\b.{0,35}\breply[- ]?to\b", "From and Reply-To identity are explicitly inconsistent"),
        ("low-reputation-sender-email", r"\b(?:low|poor|bad|weak|unknown)[- ]+(?:sender[- ]+|domain[- ]+)?reputation\b|\bsender\b.{0,55}\blow[- ]+reputation\b", "The sender or domain has explicit low-reputation evidence"),
        ("suspicious-link-email", r"\b(?:untrusted|suspicious|risky|unknown|unrecognized|unexpected)\s+(?:link|url|destination|domain)|\b(?:link|url|destination)\b.{0,55}\b(?:untrusted|suspicious|risky|unknown|unrecognized|unexpected)\b", "The message contains an explicitly untrusted or suspicious destination"),
        ("suspicious-attachment-email", r"\b(?:unexpected|suspicious|unknown|untrusted|unrecognized)\s+attachment\b|\battachment\b.{0,55}\b(?:unexpected|suspicious|unknown|untrusted|unrecognized)\b", "The message contains an explicitly unexpected or suspicious attachment"),
        ("unscannable-content-email", r"\b(?:could not|cannot|can't|unable to|failed to)\s+(?:be )?scan(?:ned)?\b|\bunscannable (?:content|message|attachment)\b", "Message content could not be scanned"),
        ("unusual-request-email", r"\b(?:outside|not part of|bypasses?)\b.{0,55}\b(?:normal|usual|standard|approved)\s+(?:process|procedure|workflow|policy)\b|\bunusual request\b", "The request is explicitly outside the normal process"),
        ("pressure-secrecy-email", r"\b(?:immediate|immediately|urgent|urgently|right away|now|today)\b.{0,120}\b(?:keep|remain|stay)\b.{0,30}\b(?:secret|private|confidential|quiet)\b|\bkeep\b.{0,30}\b(?:secret|private|confidential|quiet)\b.{0,120}\b(?:immediate|immediately|urgent|urgently|right away|now|today)\b", "The request combines time pressure with an instruction to keep it secret"),
        ("reconnaissance-email", r"\b(?:who|which person|what team)\b.{0,90}\b(?:approve|authorize|handle|manage)\w*\b.{0,90}\b(?:payment|wire|transfer|remote access)|\b(?:payment approvers?|approval limits?|remote[- ]access (?:users?|staff|details?))\b", "The sender probes payment authority, approval limits, or remote-access roles"),
    )
    for flag, pattern, reason in checks:
        if re.search(pattern, text, re.I | re.S):
            return flag, reason

    if any(_truthy(email_data.get(k)) for k in ("new_sender", "first_contact", "sender_unseen")):
        return "unexpected-contact-email", "Mailbox history marks this as a first or previously unseen contact"
    return "", ""


def evaluate_second_layer_behavioral_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    """Return at most one strongest missing-family floor per category."""
    hits: list[SecurityRuleHit] = []

    phishing = _phishing_reason(email_data, text)
    if phishing:
        hits.append(_hit("behavioral-phishing-account-access", "Phishing", "account-access-lure", phishing))

    scam = _scam_reason(text)
    if scam:
        hits.append(_hit("behavioral-scam-advance-payment", "Scam / Fraud", "fraud-action-lure", scam))

    impersonation = _identity_impersonation_reason(email_data, text)
    if impersonation:
        hits.append(_hit("behavioral-impersonation-channel-mismatch", "Impersonation", "impersonation-lure", impersonation))

    spam_flag, spam_reason = _spam_reason(email_data, text)
    if spam_flag:
        hits.append(_hit(f"behavioral-{spam_flag}", "Spam", spam_flag, spam_reason))

    suspicious_flag, suspicious_reason = _suspicious_reason(email_data, text)
    if suspicious_flag:
        hits.append(_hit(f"behavioral-{suspicious_flag}", "Suspicious", suspicious_flag, suspicious_reason))

    return hits
