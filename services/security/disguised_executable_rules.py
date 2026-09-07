"""Type 2: detect executable attachments disguised as harmless files."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_RUNNABLE_EXTENSIONS = (
    ".exe", ".scr", ".com", ".cpl", ".dll", ".msi", ".msp", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".jar", ".lnk", ".url", ".reg", ".sh", ".command", ".desktop", ".app",
)
_BENIGN_EXTENSIONS = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".csv", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".mp3", ".mp4",
)
_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_DANGEROUS_MIMES = {
    "application/x-msdownload", "application/x-dosexec", "application/x-executable",
    "application/vnd.microsoft.portable-executable", "application/x-msi",
    "application/java-archive", "application/x-sh", "application/x-shellscript",
}
_DOUBLE_EXTENSION_RE = re.compile(
    r"(?:pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|webp|svg|mp3|mp4)"
    r"(?:[.\s_-]+)(?:exe|scr|com|cpl|dll|msi|bat|cmd|ps1|vbs|js|jse|wsf|hta|jar|lnk|url)$",
    re.I,
)


def _bytes(value, limit: int = 4096) -> bytes:
    if isinstance(value, str):
        return value[:limit].encode("utf-8", errors="ignore")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value[:limit])
    return b""


def _normalized_filename(value) -> tuple[str, bool, bool]:
    original = unicodedata.normalize("NFKC", str(value or "")).casefold()
    has_bidi = any(char in _BIDI_CONTROLS for char in original)
    has_hidden_control = any(unicodedata.category(char) == "Cc" for char in original)
    visible = "".join(
        char for char in original
        if char not in _BIDI_CONTROLS and unicodedata.category(char) != "Cc"
    ).strip().rstrip(". ")
    return visible, has_bidi, has_hidden_control


def _payload_kind(sample: bytes) -> str:
    if len(sample) >= 2 and sample[:2] == b"MZ":
        return "Windows PE executable content"
    if sample.startswith(b"\x7fELF"):
        return "ELF executable content"
    if sample.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
        return "Mach-O executable content"
    if sample.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"):
        return "Windows shortcut content"
    first_line = sample[:256].decode("utf-8", errors="ignore").casefold().splitlines()[:1]
    if first_line and re.match(r"^#!\s*/(?:usr/)?bin/(?:ba|z|k|c|fi)?sh\b", first_line[0]):
        return "shell-script content"
    return ""


def _disguise_reason(attachment: Mapping) -> str:
    filename, has_bidi, has_hidden_control = _normalized_filename(attachment.get("filename"))
    content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
    runnable_suffix = next((ext for ext in _RUNNABLE_EXTENSIONS if filename.endswith(ext)), "")
    benign_suffix = next((ext for ext in _BENIGN_EXTENSIONS if filename.endswith(ext)), "")

    if _DOUBLE_EXTENSION_RE.search(filename):
        return "harmless-looking double extension hides a runnable file type"
    if (has_bidi or has_hidden_control) and (
        runnable_suffix or any(ext in filename for ext in _RUNNABLE_EXTENSIONS)
    ):
        return "Unicode/control characters conceal a runnable filename"
    if runnable_suffix and str(attachment.get("filename") or "").casefold().rstrip() != filename:
        return "trailing dots, spaces, or controls conceal a runnable extension"
    if content_type in _DANGEROUS_MIMES and (benign_suffix or not runnable_suffix):
        return f"{content_type} executable MIME type conflicts with the displayed filename"

    payload = _payload_kind(_bytes(attachment.get("data")))
    if payload and (benign_suffix or not runnable_suffix):
        return f"{payload} is disguised by a non-runnable filename"
    return ""


def evaluate_disguised_executable_rules(attachments) -> list[SecurityRuleHit]:
    hits: list[SecurityRuleHit] = []
    for index, attachment in enumerate(attachments or []):
        if not isinstance(attachment, Mapping):
            continue
        reason = _disguise_reason(attachment)
        if not reason:
            continue
        filename = str(attachment.get("filename") or f"attachment {index + 1}").strip()
        hits.append(SecurityRuleHit(
            rule_id="type2-disguised-executable",
            points=100,
            reason=f"Disguised executable detected: {filename} ({reason})",
            categories=("Malware",),
            strong_flag="dangerous-attachment",
        ))
    return hits
