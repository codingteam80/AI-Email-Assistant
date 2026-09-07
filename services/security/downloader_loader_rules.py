"""Type 5: deterministic detection of downloader/loader email behavior."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_REMOTE_RUNNABLE_RE = re.compile(
    r"https?://[^\s/<>\"']+/[^\s<>\"'?#]*\.(?:exe|scr|com|cpl|dll|msi|msp|bat|cmd|ps1|vbs|js|jse|"
    r"wsf|hta|jar|lnk|url|iso|img)(?=$|[?#])(?:[?#][^\s<>\"']*)?",
    re.I,
)
_DOWNLOAD_ACTION_RE = re.compile(
    r"\b(?:download|fetch|retrieve|get|save)\b.{0,100}\b(?:run|execute|launch|open|install|start|load)\b"
    r"|\b(?:run|execute|launch|open|install|start|load)\b.{0,100}\b(?:downloaded|download|payload|installer|file)\b",
    re.I | re.S,
)
_LOADER_LANGUAGE_RE = re.compile(
    r"\b(?:second[- ]stage payload|next[- ]stage payload|stage[- ]two payload|payload loader|"
    r"download(?:er)? stub|bootstrap loader|reflective load(?:er|ing)?|load shellcode|"
    r"fetch and execute|download and execute|download and run)\b",
    re.I,
)
_ACTIVE_FILE_CONTEXT_RE = re.compile(
    r"\b(?:payload|loader|downloader|executable|installer|script|shellcode|stage[- ](?:one|two|1|2)|"
    r"\.exe|\.scr|\.com|\.dll|\.msi|\.bat|\.cmd|\.ps1|\.vbs|\.js|\.hta|\.jar)\b",
    re.I,
)
_SCRIPT_DOWNLOAD_RE = re.compile(
    r"\b(?:invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadstring|downloadfile|"
    r"webclient|bitsadmin|certutil)\b"
    r"|\b(?:curl|wget)\b.{0,180}\bhttps?://"
    r"|\bmshta(?:\.exe)?\s+https?://"
    r"|\bregsvr32(?:\.exe)?\b.{0,180}\bhttps?://"
    r"|\brundll32(?:\.exe)?\b.{0,180}\bhttps?://",
    re.I | re.S,
)
_EXECUTION_RE = re.compile(
    r"\b(?:invoke-expression|iex|start-process|createprocess|shell(?:execute)?|wscript\.shell|"
    r"subprocess|os\.system|cmd(?:\.exe)?\s*/c|powershell(?:\.exe)?\s+-)\b",
    re.I,
)
_HTML_SMUGGLING_RE = re.compile(
    r"(?:createobjecturl|new\s+blob|uint8array|atob\s*\(|fromcharcode).{0,500}"
    r"(?:download\s*=|\.download\s*\(|mssaveblob|application/octet-stream)",
    re.I | re.S,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:malicious downloader|malware downloader|payload downloader|malicious loader|"
    r"malware loader|dropper|second[- ]stage loader|shellcode loader)\b",
    re.I,
)
_CLEAN_RE = re.compile(r"\b(?:clean|benign|safe|simulation only|not malicious|no payload)\b", re.I)
_TEXT_ATTACHMENT_EXTENSIONS = (
    ".txt", ".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".hta", ".html", ".htm", ".svg", ".url", ".desktop", ".sh", ".py",
)
_MAX_SAMPLE = 512 * 1024


def _sample(attachment: Mapping) -> str:
    filename = str(attachment.get("filename") or "").casefold()
    content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
    if not filename.endswith(_TEXT_ATTACHMENT_EXTENSIONS) and content_type not in {
        "text/plain", "text/html", "application/javascript", "application/x-powershell"
    }:
        return ""
    data = attachment.get("data")
    if isinstance(data, str):
        return data[:_MAX_SAMPLE]
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data[:_MAX_SAMPLE]).decode("utf-8", errors="ignore")
    return ""


def _metadata_reason(email_data: Mapping, attachments) -> str:
    sources = [email_data] + [item for item in (attachments or []) if isinstance(item, Mapping)]
    for source in sources:
        for key in ("is_downloader", "is_loader", "downloader_detected", "loader_detected"):
            value = source.get(key)
            if value is True or (isinstance(value, (int, float)) and value == 1):
                return key.replace("_", " ")
        for key in ("verdict", "analysis", "script_analysis", "behavior_analysis"):
            value = str(source.get(key) or "").strip()
            if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
                return f"scanner behavior evidence: {value[:120]}"
    return ""


def evaluate_downloader_loader_rules(*, email_data: Mapping, text: str, urls, attachments) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data, attachments)
    combined_urls = list(urls or []) + _URL_RE.findall(str(text or ""))
    unique_urls = list(dict.fromkeys(str(value) for value in combined_urls if str(value)))
    body = str(text or "")

    if not reason and any(_REMOTE_RUNNABLE_RE.search(url) for url in unique_urls):
        reason = "email delivers a direct remote executable or active payload"
    if (
        not reason
        and unique_urls
        and _DOWNLOAD_ACTION_RE.search(body)
        and _ACTIVE_FILE_CONTEXT_RE.search(body)
    ):
        reason = "email instructs the recipient to download and execute a remote file"
    if not reason and _LOADER_LANGUAGE_RE.search(body) and (unique_urls or _EXECUTION_RE.search(body)):
        reason = "email describes retrieval or execution of a staged payload"
    if not reason and _SCRIPT_DOWNLOAD_RE.search(body) and (
        _EXECUTION_RE.search(body) or _LOADER_LANGUAGE_RE.search(body) or unique_urls
    ):
        reason = "email body contains a command-line download/loader primitive"

    if not reason:
        for attachment in attachments or []:
            if not isinstance(attachment, Mapping):
                continue
            sample = _sample(attachment)
            if not sample:
                continue
            filename = str(attachment.get("filename") or "attachment")
            if _HTML_SMUGGLING_RE.search(sample):
                reason = f"HTML attachment constructs a downloadable payload: {filename}"
                break
            if _SCRIPT_DOWNLOAD_RE.search(sample) and (
                _EXECUTION_RE.search(sample) or _LOADER_LANGUAGE_RE.search(sample) or _URL_RE.search(sample)
            ):
                reason = f"attachment contains download/loader behavior: {filename}"
                break

    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="type5-downloader-loader-email",
        points=100,
        reason=f"Downloader or loader email detected ({reason})",
        categories=("Malware",),
        strong_flag="dangerous-attachment",
    )]
