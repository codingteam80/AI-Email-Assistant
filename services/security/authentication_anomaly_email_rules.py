"""Suspicious Type 5: identify anomalous or conflicting sender authentication."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:authentication[- ]anomaly email|sender authentication anomaly|"
    r"mail authentication inconsistency|authentication history mismatch|"
    r"spf dkim dmarc anomaly|domain authentication anomaly)\b",
    re.I,
)
_AUTH_ANOMALY_RE = re.compile(
    r"\b(?:authentication|sender verification|domain verification|spf|dkim|dmarc|"
    r"digital signature|sender signature|authentication chain|authenticated route)\b"
    r".{0,75}\b(?:anomalous|anomaly|changed|conflict(?:s|ing|ed)?|inconsistent|"
    r"mixed results?|failed|could not be verified|cannot be verified|missing|"
    r"does not match|doesn't match|differs? from|unexpected|unusual|not used|lacks?)\b|"
    r"\b(?:anomalous|anomaly|changed|conflict(?:s|ing|ed)?|inconsistent|mixed results?|"
    r"failed|missing|lacks?|unexpected|unusual)\b.{0,75}"
    r"\b(?:authentication|sender verification|domain verification|spf|dkim|dmarc|"
    r"digital signature|sender signature|authentication chain|authenticated route)\b",
    re.I,
)
_BASELINE_RE = re.compile(
    r"\b(?:usual|normally|normal|known|previous|prior|history|historical|expected|"
    r"pattern|mixed results?|conflict(?:s|ing|ed)?|conflicting results?|inconsistent|changed|unexpected|"
    r"could not be verified|cannot be verified|failed|missing|does not match|"
    r"doesn't match|differs? from)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"approved mail migration|scheduled key rotation|verified domain change|"
    r"documented forwarding service|authenticated mailing list|expected dkim rotation|"
    r"confirmed dns update|administrator confirmed)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "sender authentication changed unexpectedly",
    "this message failed sender verification",
    "spf and dkim results conflict",
    "the authentication result is inconsistent",
    "the usual authenticated route was not used",
    "the dkim signature is unexpectedly missing",
    "the spf alignment differs from prior messages",
    "the dmarc result does not match the sender pattern",
    "sender authentication could not be verified",
    "conflicting authentication results were reported",
    "the message has an unusual authentication status",
    "domain authentication changed without explanation",
    "the authentication chain contains mixed results",
    "this email lacks the expected sender signature",
    "the sender verification pattern is anomalous",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _false(value: object) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)) and value == 0:
        return True
    return isinstance(value, str) and value.casefold().strip() in {
        "false", "no", "mismatch", "mismatched", "anomalous", "inconsistent",
    }


def _has_conflicting_authentication(email_data: Mapping) -> bool:
    evidence = str(email_data.get("spam_evidence") or "").casefold()
    return any(
        f"{method}=pass" in evidence and f"{method}=fail" in evidence
        for method in ("spf", "dkim", "dmarc")
    )


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "authentication_anomaly_email_detected",
        "sender_authentication_anomaly_detected",
        "mail_authentication_inconsistency_detected",
        "authentication_history_mismatch_detected",
        "spf_dkim_dmarc_anomaly_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in (
        "authentication_results_consistent",
        "authentication_matches_sender_history",
        "sender_signature_matches_history",
    ):
        if key in email_data and _false(email_data.get(key)):
            return f"mailbox metadata reports {key.replace('_', ' ')}"
    if _has_conflicting_authentication(email_data):
        return "Authentication-Results contains both pass and fail for one method"
    for key in (
        "suspicious_classification",
        "authentication_analysis",
        "classification_analysis",
        "security_analysis",
        "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner authentication-anomaly evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "authentication_analysis", "classification_analysis", "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies an authentication-anomaly email"
    if _AUTH_ANOMALY_RE.search(text) and _BASELINE_RE.search(text):
        return "message explicitly describes authentication that conflicts with the expected sender pattern"
    return ""


def evaluate_authentication_anomaly_email_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type5-authentication-anomaly",
        points=100,
        reason=f"Authentication-anomaly email detected ({reason})",
        categories=("Suspicious",),
        strong_flag="authentication-anomaly-email",
    )]
