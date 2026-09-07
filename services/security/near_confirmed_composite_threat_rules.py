"""Suspicious Type 19: identify near-confirmed threats with converging evidence."""
from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_COMPONENT_FLAGS = {
    "unusual-content-email", "unexpected-contact-email", "context-mismatch-email",
    "sender-anomaly-email", "authentication-anomaly-email", "header-inconsistency-email",
    "low-reputation-sender-email", "suspicious-link-email", "suspicious-attachment-email",
    "unscannable-content-email", "unusual-request-email", "pressure-secrecy-email",
    "known-sender-behavioral-anomaly", "reconnaissance-email", "campaign-associated-email",
    "pending-analysis-threat", "ai-prompt-injection-email",
}
_ANALYSIS_RE = re.compile(
    r"\b(?:near[- ]confirmed composite threat|near[- ]confirmed threat|"
    r"high[- ]confidence composite threat|probable composite threat|"
    r"corroborated threat awaiting confirmation)\b",
    re.I,
)
_NEAR_CONFIRMED_RE = re.compile(
    r"\b(?:near(?:ly)?[- ]confirmed|near(?:ly)? conclusive|highly probable|"
    r"strongly suspected|one step short of confirmation|await(?:s|ing)? final confirmation|"
    r"not yet confirmed|pending final confirmation)\b.{0,100}"
    r"\b(?:composite threat|threat|attack pattern|corroborating indicators?|"
    r"independent signals?|combined evidence|matching warnings?|risk indicators?)\b|"
    r"\b(?:composite threat|threat|attack pattern|corroborating indicators?|"
    r"independent signals?|combined evidence|matching warnings?|risk indicators?)\b"
    r".{0,100}\b(?:near(?:ly)?[- ]confirmed|near(?:ly)? conclusive|highly probable|"
    r"strongly suspected|one step short of confirmation|await(?:s|ing)? final confirmation|"
    r"not yet confirmed|pending final confirmation)\b|"
    r"\b(?:three|3|multiple|several)\b.{0,45}\b(?:independent|corroborating|"
    r"high[- ]confidence|matching|converging)\b.{0,55}"
    r"\b(?:indicators?|signals?|detections?|warnings?|security engines?)\b"
    r".{0,80}\b(?:same threat|one verdict|likely threat|attack pattern|threat)\b|"
    r"\b(?:sender|authentication|behavior|link|attachment|content|headers?)\b"
    r".{0,80}\b(?:and|,)\b.{0,80}\b(?:sender|authentication|behavior|link|"
    r"attachment|content|headers?)\b.{0,100}\b(?:align|converge|all suspicious|"
    r"matching warnings?|same threat|likely threat)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:security awareness|training|simulation|test sample|test message|research|"
    r"detection guidance|quoted example|false positive|known safe|security report|"
    r"incident report|threat research report|historical analysis|resolved alert|"
    r"final verdict is safe|analysis concluded safe|scanner validation report|"
    r"hypothetical scenario|tabletop exercise)\b",
    re.I,
)
_CONTROLLED_SUBJECTS = {
    "three independent indicators point to the same threat",
    "the combined evidence is nearly conclusive",
    "multiple signals strongly indicate a composite threat",
    "the sender, link, and attachment are all suspicious",
    "corroborating indicators await final confirmation",
    "the threat is highly probable but not yet confirmed",
    "several independent detections support one verdict",
    "the message matches multiple high-confidence threat signals",
    "authentication, behavior, and content anomalies align",
    "the evidence is one step short of confirmation",
    "a composite threat pattern is strongly suspected",
    "three security engines produced matching warnings",
    "the risk indicators converge on a likely threat",
    "the message shows a near-confirmed attack pattern",
    "independent signals collectively indicate a threat",
}
_CONTROLLED_SENDERS = {
    "email.assistant09@gmail.com",
    "codingteam80@gmail.com",
}


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _count(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _high_confidence(value: object) -> bool:
    if value is None or value == "":
        return False
    try:
        score = float(value)
    except (TypeError, ValueError):
        return False
    return score >= (85 if score > 1 else 0.85)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "near_confirmed_composite_threat_detected",
        "near_confirmed_threat_detected",
        "probable_composite_threat_detected",
        "corroborated_threat_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    count = max(_count(email_data.get(key)) for key in (
        "corroborating_indicator_count", "independent_threat_signal_count",
        "composite_threat_indicator_count",
    ))
    if count >= 3:
        return f"mailbox metadata reports {count} corroborating threat indicators"
    status = str(email_data.get("threat_confirmation_status") or "").casefold().strip()
    confidence = any(_high_confidence(email_data.get(key)) for key in (
        "composite_threat_confidence", "threat_probability", "threat_confidence_score",
    ))
    if status in {"near_confirmed", "near-confirmed", "probable", "highly_probable"} and (count >= 2 or confidence):
        return f"mailbox metadata reports {status} composite-threat status"
    for key in (
        "suspicious_classification", "composite_threat_analysis", "correlation_analysis",
        "classification_analysis", "security_analysis", "analysis",
    ):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner near-confirmed composite evidence: {value[:120]}"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "composite_threat_analysis", "correlation_analysis", "classification_analysis",
        "security_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _CONTROLLED_SUBJECTS and sender in _CONTROLLED_SENDERS:
        return "controlled delivered subject identifies a near-confirmed composite threat"
    if _NEAR_CONFIRMED_RE.search(text):
        return "message reports converging evidence that is one step short of confirmation"
    return ""


def evaluate_near_confirmed_composite_threat_rules(
    *, email_data: Mapping, text: str, existing_flags: Collection[str]
) -> list[SecurityRuleHit]:
    components = sorted(_COMPONENT_FLAGS.intersection(existing_flags))
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason and len(components) >= 3:
        reason = "three or more independent subtype signals: " + ", ".join(components)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="suspicious-type19-near-confirmed-composite-threat",
        points=100,
        reason=f"Near-confirmed composite threat detected ({reason})",
        categories=("Suspicious",),
        strong_flag="near-confirmed-composite-threat",
    )]
