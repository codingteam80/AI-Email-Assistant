"""Type 4: bounded structural detection of weaponized documents."""
from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_DOCUMENT_EXTENSIONS = (
    ".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm",
    ".xlsb", ".xltm", ".ppt", ".pptx", ".pptm", ".potm", ".pps", ".ppsm",
    ".rtf", ".pdf",
)
_DOCUMENT_MIMES = {
    "application/pdf", "application/rtf", "text/rtf", "application/msword",
    "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
}
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MAX_DOCUMENT_BYTES = 30 * 1024 * 1024
_MAX_ZIP_MEMBERS = 512
_MAX_MEMBER_SAMPLE = 2 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED = 80 * 1024 * 1024
_PDF_ACTIVE_RE = re.compile(
    rb"/(?:JavaScript|JS|Launch|OpenAction|AA)\b|/S\s*/(?:JavaScript|Launch)\b",
    re.I,
)
_RTF_ACTIVE_RE = re.compile(
    rb"\\(?:object|objdata|objemb|objlink|datastore)\b|\\field\b.{0,256}\bDDE(?:AUTO)?\b",
    re.I | re.S,
)
_OLE_ACTIVE_MARKERS = (
    b"vba", b"_vba_project", b"macros", b"powershell", b"cmd.exe", b"wscript.shell",
    b"autoopen", b"document_open", b"workbook_open", b"ddeauto",
)
_XML_ACTIVE_RE = re.compile(
    rb"\bDDE(?:AUTO)?\b|mso:OLEObject|<oleObject\b|<embeddedFont\b",
    re.I,
)
_MALICIOUS_ANALYSIS_RE = re.compile(
    r"\b(?:weaponized|malicious|exploit|shellcode|macro malware|malicious macro|"
    r"remote template injection|ole exploit|dde attack)\b",
    re.I,
)
_CLEAN_RE = re.compile(r"\b(?:clean|benign|safe|no active content|no macros?|not malicious)\b", re.I)


def _bytes(value) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", errors="ignore")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return b""


def _metadata_reason(attachment: Mapping) -> str:
    for key in ("is_weaponized", "weaponized", "contains_malicious_macro", "malicious_macro"):
        value = attachment.get(key)
        if value is True or (isinstance(value, (int, float)) and value == 1):
            return key.replace("_", " ")
    for key in ("document_verdict", "document_analysis", "office_analysis", "pdf_analysis", "analysis"):
        value = str(attachment.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _MALICIOUS_ANALYSIS_RE.search(value):
            return f"document scanner evidence: {value[:120]}"
    if attachment.get("contains_macros") is True and str(attachment.get("macro_verdict") or "").casefold() in {
        "malicious", "weaponized", "blocked", "infected"
    }:
        return "malicious macro verdict"
    return ""


def _inspect_ooxml(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ZIP_MEMBERS:
            return "document package contains an unsafe number of parts"
        total = 0
        names = [info.filename.replace("\\", "/").casefold() for info in infos]
        if any(name.endswith("vbaproject.bin") for name in names):
            return "Office document contains an embedded VBA project"
        if any("/embeddings/" in f"/{name}" and name.endswith((".bin", ".exe", ".dll")) for name in names):
            return "Office document contains an embedded OLE/binary object"
        if any("macrosheets/" in name or "xlm" in name for name in names):
            return "spreadsheet contains an Excel 4.0 macro sheet"
        for info in infos:
            total += max(0, info.file_size)
            if total > _MAX_TOTAL_UNCOMPRESSED:
                return "document package expands beyond the safe inspection limit"
            name = info.filename.replace("\\", "/").casefold()
            if info.is_dir() or info.file_size > _MAX_MEMBER_SAMPLE:
                continue
            if not name.endswith((".xml", ".rels")):
                continue
            sample = archive.read(info)[:_MAX_MEMBER_SAMPLE]
            if _XML_ACTIVE_RE.search(sample):
                return f"active DDE/OLE content in Office part: {info.filename}"
            if name.endswith(".rels") and re.search(
                rb'TargetMode\s*=\s*["\']External["\']', sample, re.I
            ) and re.search(rb"(?:attachedTemplate|oleObject|externalLink)", sample, re.I):
                return f"external active-content relationship in Office part: {info.filename}"
    return ""


def _inspect_document(filename: str, content_type: str, data: bytes) -> str:
    if not data or len(data) > _MAX_DOCUMENT_BYTES:
        return ""
    lower = data[:_MAX_MEMBER_SAMPLE].lower()
    if data.startswith(b"%PDF") or filename.endswith(".pdf") or content_type == "application/pdf":
        if _PDF_ACTIVE_RE.search(data[:_MAX_DOCUMENT_BYTES]):
            return "PDF contains automatic JavaScript, launch, or open-action content"
    if lower.lstrip().startswith(b"{\\rtf") or filename.endswith(".rtf"):
        if _RTF_ACTIVE_RE.search(data[:_MAX_DOCUMENT_BYTES]):
            return "RTF contains an embedded object, object data, or DDE field"
    if data.startswith(_OLE_MAGIC):
        if any(marker in lower for marker in _OLE_ACTIVE_MARKERS):
            return "legacy Office document contains macro/execution markers"
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            return _inspect_ooxml(data)
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    return ""


def evaluate_weaponized_document_rules(attachments) -> list[SecurityRuleHit]:
    hits: list[SecurityRuleHit] = []
    for index, attachment in enumerate(attachments or []):
        if not isinstance(attachment, Mapping):
            continue
        filename = str(attachment.get("filename") or f"document {index + 1}").strip()
        lower_name = filename.casefold()
        content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
        if not lower_name.endswith(_DOCUMENT_EXTENSIONS) and content_type not in _DOCUMENT_MIMES:
            continue
        reason = _metadata_reason(attachment) or _inspect_document(
            lower_name, content_type, _bytes(attachment.get("data"))
        )
        if reason:
            hits.append(SecurityRuleHit(
                rule_id="type4-weaponized-document",
                points=100,
                reason=f"Weaponized document detected: {filename} ({reason})",
                categories=("Malware",),
                strong_flag="dangerous-attachment",
            ))
    return hits
