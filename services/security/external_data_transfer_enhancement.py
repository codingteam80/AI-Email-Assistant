"""MailMind post-V9 enhancement for covert transfer of internal data.

The imported V9 rules remain unchanged.  This layer covers a narrow gap where
an email instructs the recipient to move company/internal data to a personal or
otherwise unmanaged destination while also asking them to bypass or conceal the
normal IT/security process.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit

_TRANSFER_ACTION_RE = re.compile(
    r"\b(?:copy|move|upload|send|transfer|export|sync|share|forward|back\s*up|mirror)\b",
    re.I,
)
_INTERNAL_DATA_RE = re.compile(
    r"\b(?:internal|company|corporate|confidential|sensitive|private|restricted|"
    r"customer|client|employee|payroll|financial|project|source[- ]?code|proprietary)\b"
    r".{0,70}\b(?:file|files|document|documents|data|records?|spreadsheet|spreadsheets|"
    r"archive|archives|repository|repo|materials?|information)\b|"
    r"\b(?:file|files|document|documents|data|records?|spreadsheet|spreadsheets|"
    r"archive|archives|repository|repo|materials?|information)\b.{0,70}"
    r"\b(?:internal|company|corporate|confidential|sensitive|private|restricted|"
    r"customer|client|employee|payroll|financial|project|source[- ]?code|proprietary)\b",
    re.I,
)
_UNMANAGED_DESTINATION_RE = re.compile(
    r"\b(?:personal|private|non[- ]?company|external|unmanaged|off[- ]?network)\b"
    r".{0,55}\b(?:cloud(?:[- ]storage)?|storage|drive|account|email|mailbox|device|usb|"
    r"dropbox|folder|server|repository|repo)\b|"
    r"\b(?:personal\s+(?:google\s+drive|onedrive|dropbox|icloud|email|mailbox|account)|"
    r"off[- ]?network|outside\s+(?:the\s+)?company\s+(?:network|storage|systems?))\b",
    re.I,
)
_EVASION_RE = re.compile(
    r"\b(?:do\s+not|don't|dont|avoid|skip|bypass|without)\b.{0,85}"
    r"\b(?:it\s+ticket|ticket|it\b|security|compliance|approval|review|manager|admin|"
    r"project\s+channel|team\s+channel|audit|logging|dlp|normal\s+process|approved\s+process)\b|"
    r"\b(?:keep|keep\s+this|keep\s+it)\b.{0,30}\b(?:quiet|private|secret|confidential)\b|"
    r"\b(?:do\s+not|don't|dont|avoid)\b.{0,50}\b(?:mention|tell|notify|report|disclose)\b",
    re.I,
)
_PROTECTIVE_CONTEXT_RE = re.compile(
    r"\b(?:do\s+not|don't|dont|never|avoid)\s+(?:please\s+)?(?:copy|move|upload|send|transfer|"
    r"export|sync|share|forward)\b|"
    r"\b(?:security\s+(?:awareness|training|policy|guidance|review|incident|alert)|"
    r"data[- ]loss\s+prevention|dlp\s+(?:policy|alert)|reported\s+(?:to|through)\s+it|"
    r"approved\s+(?:migration|transfer|exception)|authorized\s+(?:migration|transfer|exception)|"
    r"blocked|quarantined|prevented|stopped)\b",
    re.I,
)


def evaluate_external_data_transfer_enhancement(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    """Detect covert internal-data transfer to an unmanaged destination.

    The enhancement intentionally requires a conjunction of (1) company/internal
    data, (2) a transfer action to a personal/external destination, and (3)
    concealment or process-bypass language.  This keeps ordinary cloud sharing,
    backups, policy reminders, and approved migrations out of scope.
    """
    del email_data  # Provider-neutral by design.
    value = str(text or "")
    if not value or _PROTECTIVE_CONTEXT_RE.search(value):
        return []
    if not _TRANSFER_ACTION_RE.search(value):
        return []
    if not _INTERNAL_DATA_RE.search(value):
        return []
    if not _UNMANAGED_DESTINATION_RE.search(value):
        return []
    if not _EVASION_RE.search(value):
        return []

    return [
        SecurityRuleHit(
            rule_id="enhancement-external-data-transfer-evasion",
            points=100,
            reason=(
                "Recipient is directed to move internal/company data to a personal or "
                "unmanaged destination while bypassing or concealing the normal IT/security process"
            ),
            categories=("Suspicious",),
            strong_flag="external-data-transfer-evasion",
        )
    ]
