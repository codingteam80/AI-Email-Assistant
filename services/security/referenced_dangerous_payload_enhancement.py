"""MailMind post-V9 enhancement: detect explicitly referenced dangerous payload delivery.

This module intentionally does not alter the imported V9 security rules.  It
covers a provider-normalization gap where a message tells the recipient to
open/run/download a specifically named executable payload, but the provider no
longer exposes that payload in attachment metadata (for example after stripping
or transport normalization).
"""
from __future__ import annotations

import re
from typing import Mapping

from services.security.models import SecurityRuleHit

_DANGEROUS_FILENAME_RE = re.compile(
    r"(?<![\w@])(?P<filename>[a-z0-9][a-z0-9_.()+,&-]{0,80}\."
    r"(?:exe|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|cpl|msi|msp|lnk|url))"
    r"\b",
    re.IGNORECASE,
)
_DELIVERY_CONTEXT_RE = re.compile(
    r"\b(?:attach(?:ed|ment)?|download(?:ed|ing)?|file|payload|installer|setup|update|"
    r"invoice|document|package)\b",
    re.IGNORECASE,
)
_RECIPIENT_ACTION_RE = re.compile(
    r"\b(?:please\s+)?(?:open|run|execute|launch|install|download|double[- ]?click|"
    r"view|review|start)\b|\bmust\s+be\s+(?:opened|run|executed|launched|installed)\b",
    re.IGNORECASE,
)
_PROTECTIVE_CONTEXT_RE = re.compile(
    r"\b(?:do\s+not|don't|dont|never|avoid)\s+(?:open|run|execute|launch|install|download)|"
    r"\b(?:blocked|quarantined|removed|deleted|sanitized|neutralized)\b|"
    r"\b(?:security|malware|threat|incident|forensic|sandbox)\s+(?:analysis|report|review|alert)\b|"
    r"\b(?:detected|identified|flagged)\s+as\s+(?:malware|malicious|a\s+threat)\b",
    re.IGNORECASE,
)


def _candidate_sentences(text: str) -> list[str]:
    value = str(text or "")
    # Keep bounded sentence-ish windows. Email line breaks often separate a CTA
    # from explanatory prose, and we only need local evidence around a filename.
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|[\r\n]+", value) if part.strip()]


def evaluate_referenced_dangerous_payload_enhancement(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    """Return a Malware hit for a concrete recipient-directed executable lure.

    A filename mention alone is not enough.  The same local sentence/window must
    also carry delivery/file context plus a recipient action.  Protective or
    analytical wording suppresses the enhancement so benign security discussion
    is not reclassified as malware delivery.
    """
    del email_data  # Reserved for future provider-neutral evidence; no provider branching.
    for sentence in _candidate_sentences(text):
        match = _DANGEROUS_FILENAME_RE.search(sentence)
        if not match:
            continue
        if _PROTECTIVE_CONTEXT_RE.search(sentence):
            continue
        if not _DELIVERY_CONTEXT_RE.search(sentence):
            continue
        if not _RECIPIENT_ACTION_RE.search(sentence):
            continue
        filename = match.group("filename").strip(" .,:;()[]{}'\"")
        return [
            SecurityRuleHit(
                rule_id="enhancement-referenced-dangerous-payload-delivery",
                points=100,
                reason=(
                    "Recipient is directed to interact with a specifically named "
                    f"executable payload ({filename}) even though provider attachment metadata is absent"
                ),
                categories=("Malware",),
                strong_flag="referenced-dangerous-payload-delivery",
            )
        ]
    return []
