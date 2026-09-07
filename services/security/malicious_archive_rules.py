"""Type 3: bounded, non-executing inspection of malicious archives."""
from __future__ import annotations

import gzip
import io
import re
import tarfile
import zipfile
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tgz", ".tar.gz", ".gz", ".7z", ".rar")
_RUNNABLE_RE = re.compile(
    r"\.(?:exe|scr|com|cpl|dll|msi|msp|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|"
    r"hta|jar|lnk|url|reg|sh|command|desktop|app)(?:[.\s]*$)", re.I,
)
_DOUBLE_EXTENSION_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|webp|svg|mp3|mp4)"
    r"(?:[.\s_-]+)(?:exe|scr|com|cpl|dll|msi|bat|cmd|ps1|vbs|js|jse|wsf|hta|jar|lnk|url)$",
    re.I,
)
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
_MAX_MEMBERS = 256
_MAX_MEMBER_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200


def _coerce_bytes(value) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", errors="ignore")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return b""


def _payload_reason(name: str, sample: bytes = b"") -> str:
    normalized = str(name or "").replace("\\", "/").strip().rstrip(". ")
    if normalized.startswith("/") or re.match(r"^[a-z]:/", normalized, re.I) or "../" in f"/{normalized}/":
        return f"archive path traversal entry: {name}"
    if _DOUBLE_EXTENSION_RE.search(normalized):
        return f"disguised executable member: {name}"
    if _RUNNABLE_RE.search(normalized):
        return f"runnable member: {name}"
    if _EICAR in sample:
        return f"known malicious test signature in member: {name}"
    if sample.startswith(b"MZ"):
        return f"Windows executable content in member: {name}"
    if sample.startswith(b"\x7fELF"):
        return f"ELF executable content in member: {name}"
    if sample.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
        return f"Mach-O executable content in member: {name}"
    first = sample[:256].decode("utf-8", errors="ignore").casefold().splitlines()[:1]
    if first and re.match(r"^#!\s*/(?:usr/)?bin/(?:ba|z|k|c|fi)?sh\b", first[0]):
        return f"shell-script content in member: {name}"
    return ""


def _metadata_members(attachment: Mapping):
    for key in ("archive_contents", "archive_members", "members", "contained_files", "file_list"):
        values = attachment.get(key)
        if not isinstance(values, (list, tuple, set)):
            continue
        for value in list(values)[:_MAX_MEMBERS]:
            if isinstance(value, Mapping):
                yield str(value.get("filename") or value.get("name") or value.get("path") or "member"), _coerce_bytes(value.get("data"))[:_MAX_MEMBER_BYTES]
            else:
                yield str(value), b""


def _inspect_zip(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_MEMBERS:
            return "archive contains an unsafe number of members"
        total = 0
        for info in infos:
            total += max(0, info.file_size)
            if total > _MAX_TOTAL_UNCOMPRESSED:
                return "archive expands beyond the safe inspection limit"
            if info.compress_size and info.file_size / info.compress_size > _MAX_COMPRESSION_RATIO:
                return f"suspicious compression ratio for member: {info.filename}"
            reason = _payload_reason(info.filename)
            if reason:
                return reason
            if info.is_dir() or info.file_size > _MAX_MEMBER_BYTES or info.flag_bits & 0x1:
                continue
            with archive.open(info) as member:
                reason = _payload_reason(info.filename, member.read(_MAX_MEMBER_BYTES))
            if reason:
                return reason
    return ""


def _inspect_tar(data: bytes) -> str:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > _MAX_MEMBERS:
            return "archive contains an unsafe number of members"
        total = 0
        for member in members:
            total += max(0, member.size)
            if total > _MAX_TOTAL_UNCOMPRESSED:
                return "archive expands beyond the safe inspection limit"
            if member.issym() or member.islnk():
                return f"archive contains a link entry: {member.name}"
            reason = _payload_reason(member.name)
            if reason:
                return reason
            if member.isfile() and member.size <= _MAX_MEMBER_BYTES:
                handle = archive.extractfile(member)
                reason = _payload_reason(member.name, handle.read(_MAX_MEMBER_BYTES) if handle else b"")
                if reason:
                    return reason
    return ""


def _inspect_attachment(attachment: Mapping) -> str:
    filename = str(attachment.get("filename") or "").casefold().strip()
    metadata_reason = next((_payload_reason(name, sample) for name, sample in _metadata_members(attachment) if _payload_reason(name, sample)), "")
    if metadata_reason:
        return metadata_reason
    data = _coerce_bytes(attachment.get("data"))
    if not data or len(data) > _MAX_ARCHIVE_BYTES:
        return ""
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            return _inspect_zip(data)
        if tarfile.is_tarfile(io.BytesIO(data)):
            return _inspect_tar(data)
        if filename.endswith(".gz"):
            expanded = gzip.decompress(data)
            if len(expanded) > _MAX_MEMBER_BYTES or len(expanded) > max(1, len(data)) * _MAX_COMPRESSION_RATIO:
                return "gzip member expands beyond the safe inspection limit"
            member_name = filename[:-3] or "gzip-member"
            return _payload_reason(member_name, expanded)
    except (OSError, EOFError, ValueError, zipfile.BadZipFile, tarfile.TarError):
        return ""
    return ""


def evaluate_malicious_archive_rules(attachments) -> list[SecurityRuleHit]:
    hits: list[SecurityRuleHit] = []
    for index, attachment in enumerate(attachments or []):
        if not isinstance(attachment, Mapping):
            continue
        filename = str(attachment.get("filename") or f"archive {index + 1}").strip()
        if not filename.casefold().endswith(_ARCHIVE_EXTENSIONS) and not any(
            key in attachment for key in ("archive_contents", "archive_members", "members", "contained_files", "file_list")
        ):
            continue
        reason = _inspect_attachment(attachment)
        if reason:
            hits.append(SecurityRuleHit(
                rule_id="type3-malicious-archive",
                points=100,
                reason=f"Malicious archive detected: {filename} ({reason})",
                categories=("Malware",),
                strong_flag="dangerous-attachment",
            ))
    return hits
