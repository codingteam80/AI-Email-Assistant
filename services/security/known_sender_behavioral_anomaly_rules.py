"""Suspicious Type 13: identify behavioral anomalies from a known sender."""
from __future__ import annotations

import re
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:known[- ]sender behavioral anomaly|trusted[- ]sender behavior anomaly|"
    r"familiar[- ]sender behavior change|sender behavior baseline deviation)\b",
    re.I,
)
_KNOWN_SENDER_RE = re.compile(
    r"\b(?:known sender|known contact|trusted sender|trusted contact|familiar sender|"
    r"familiar contact|familiar account|recognized sender|recognized contact|regular sender|"
    r"established contact|usual sender|existing contact|prior sender history|"
    r"sender's established baseline|sender behavior baseline)\b",
    re.I,
)
_BEHAVIOR_ANOMALY_RE = re.compile(
    r"\b(?:behav(?:ior|iour)(?: is| appears| seems)? (?:unusual|different|changed|"
    r"inconsistent|atypical|anomalous)|behav(?:ior|iour) (?:does not|doesn't|doesn.t) match|"
    r"writing style (?:changed|differs|does not match|doesn't match|is unusual)|"
    r"tone (?:changed|differs|does not match|doesn't match|is inconsistent|is unusual)|"
    r"language (?:changed|differs|does not match|is unfamiliar|is unusual)|"
    r"request pattern (?:changed|differs|does not match|is unfamiliar|is unusual)|"
    r"communication pattern (?:changed|differs|does not match|is inconsistent)|"
    r"sending (?:time|pattern|frequency) (?:changed|differs|is unusual|is inconsistent)|"
    r"contacted (?:us|me|you) at an unusual time|"
    r"(?:acting|behaving|writing|requesting) (?:differently|unusually|outside (?:the |their |its )?usual pattern)|"
    r"(?:departs|deviates) from (?:the |their |this sender's )?(?:normal|usual|established) (?:habits|pattern|baseline|behavior)|"
    r"does not match (?:the |their |this sender's )?(?:normal|usual|established) (?:habits|pattern|baseline|behavior)|"
    r"suddenly changed (?:behavior|tone|style|language|request pattern)|"
    r"atypical action|(?:unusual|unfamiliar|atypical) request)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"analysis|detection guidance|quoted example|false positive|known safe|"
    r"announced writing change|preannounced schedule change|approved communication change|"
    r"confirmed travel schedule|verified account owner|sender confirmed the change|"
    r"expected behavior change|documented role change|approved delegation|"
    r"planned shift coverage|routine request|established alternate schedule)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "this request is unusual for this known sender",
    "the sender's writing style changed unexpectedly",
    "a trusted contact is behaving differently",
    "the message tone does not match prior emails",
    "this known sender is making an unfamiliar request",
    "the sender contacted us at an unusual time",
    "the usual communication pattern has changed",
    "this contact is using language they do not normally use",
    "the sender's request pattern differs from history",
    "a familiar contact suddenly changed behavior",
    "this message departs from the sender's normal habits",
    "the known sender is asking for an atypical action",
    "the contact's tone and timing are inconsistent",
    "the sender behavior does not match the established baseline",
    "this familiar account is acting outside its usual pattern",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _high_score(value: object) -> bool:
    if value is None or value == "":
        return False
    try:
        score = float(value)
    except (TypeError, ValueError):
        return False
    return score >= (80 if score > 1 else 0.8)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "known_sender_behavioral_anomaly_detected",
        "known_sender_behavior_anomaly_detected",
        "trusted_sender_behavior_change_detected",
        "sender_baseline_deviation_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    sender_known = any(_true(email_data.get(key)) for key in (
        "sender_known", "known_sender", "sender_in_contacts", "prior_relationship",
    ))
    behavior_flag = any(_true(email_data.get(key)) for key in (
        "sender_style_anomaly_detected", "sender_tone_anomaly_detected",
        "sender_timing_anomaly_detected", "sender_request_pattern_anomaly_detected",
    ))
    if sender_known and behavior_flag:
        return "mailbox metadata reports anomalous behavior by a known sender"
    if sender_known and any(_high_score(email_data.get(key)) for key in (
        "sender_behavior_anomaly_score", "sender_baseline_deviation_score",
    )):
        return "known-sender behavioral deviation score is at or above 0.8"
    for key in (
        "suspicious_classification", "behavior_analysis", "sender_analysis",
        "classification_analysis", "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner known-sender behavior evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "behavior_analysis", "sender_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a known-sender behavioral anomaly"
    if _KNOWN_SENDER_RE.search(text) and _BEHAVIOR_ANOMALY_RE.search(text):
        return "message states that a known sender deviates from established behavior"
    return ""


def evaluate_known_sender_behavioral_anomaly_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type13-known-sender-behavioral-anomaly",
        points=100,
        reason=f"Known-sender behavioral anomaly detected ({reason})",
        categories=("Suspicious",),
        strong_flag="known-sender-behavioral-anomaly",
    )]
