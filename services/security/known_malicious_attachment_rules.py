"""Type 1: deterministic detection of known-malicious attachments.

This rule consumes only evidence that travels with the message (a scanner
verdict or a recognized test-virus signature).  It does not infer malware from
an arbitrary document name and never executes attachment content.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_MALICIOUS_WORD_RE = re.compile(
    r"\b(?:malicious|malware|infected|virus|trojan|ransomware|worm|rootkit|"
    r"spyware|keylogger|backdoor|dropper|exploit)\b",
    re.I,
)
_CLEAN_WORD_RE = re.compile(r"\b(?:clean|benign|safe|not malicious|no threats?)\b", re.I)
_VERDICT_KEYS = (
    "verdict", "scan_verdict", "scanner_verdict", "av_verdict", "antivirus_verdict",
    "threat", "threat_name", "malware", "malware_name", "virus", "virus_name",
    "detection", "analysis",
)
_BOOLEAN_KEYS = ("is_malicious", "malicious", "infected", "virus_found", "threat_found")


def _flatten(value) -> str:
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_flatten(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(item) for item in value)
    return str(value or "")


def _scanner_detection(attachment: Mapping) -> str:
    for key in _BOOLEAN_KEYS:
        value = attachment.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")

    for key in _VERDICT_KEYS:
        if key not in attachment:
            continue
        value = _flatten(attachment.get(key)).strip()
        # Explicit negative verdicts must win over the word "malicious" in
        # phrases such as "not malicious".
        if value and not _CLEAN_WORD_RE.search(value) and _MALICIOUS_WORD_RE.search(value):
            return value[:120]
    return ""


def evaluate_known_malicious_attachment_rules(attachments) -> list[SecurityRuleHit]:
    """Return a Malware safety-floor hit for each independently known sample."""
    hits: list[SecurityRuleHit] = []
    for index, attachment in enumerate(attachments or []):
        if not isinstance(attachment, Mapping):
            continue
        filename = str(attachment.get("filename") or f"attachment {index + 1}").strip()
        data = attachment.get("data")
        if isinstance(data, str):
            sample = data.encode("utf-8", errors="ignore")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            sample = bytes(data)
        else:
            sample = b""

        detection = "EICAR antivirus test signature" if _EICAR_SIGNATURE in sample else _scanner_detection(attachment)
        if not detection:
            continue
        hits.append(SecurityRuleHit(
            rule_id="type1-known-malicious-attachment",
            points=100,
            reason=f"Known malicious attachment detected: {filename} ({detection})",
            categories=("Malware",),
            strong_flag="dangerous-attachment",
        ))
    return hits
