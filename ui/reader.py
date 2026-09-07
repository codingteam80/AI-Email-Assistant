import base64
import concurrent.futures
import csv
import io
import functools
import hashlib
import html as html_lib
import ipaddress
import math
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from email.utils import getaddresses, parseaddr
from pathlib import Path

import streamlit as st

from email_handler.display_time import parse_timestamp

from config import (
    ATTACHMENT_MEDIA_PREVIEW_MAX_BYTES,
    ATTACHMENT_PDF_PREVIEW_MAX_BYTES,
    ATTACHMENT_TEXT_PREVIEW_MAX_BYTES,
    EMAIL_PREVIEW_CSS_CACHE_SIZE,
    ATTACHMENT_LIST_SCROLL_HEIGHT,
    EMAIL_READER_HEIGHT,
    EMAIL_SPREADSHEET_PREVIEW_HEIGHT,
    EMAIL_TABLE_PREVIEW_HEIGHT,
    EMAIL_REMOTE_IMAGE_CACHE_SIZE,
    EMAIL_REMOTE_IMAGE_MAX_BYTES,
    EMAIL_REMOTE_IMAGE_MAX_COUNT,
    EMAIL_REMOTE_IMAGE_TIMEOUT_SECONDS,
    UI_FOREGROUND_SETTLE_SECONDS,
)

from ui.markup import security_badge
from services.ui_interaction_service import arm_foreground_interaction


_AVATAR_CLASS_COUNT = 8
EMPTY_META_VALUES = {"", "none", "n/a", "na", "null", "[]", "{}"}


_REPLY_HISTORY_ON_WROTE_RE = re.compile(r"^\s*On .+ wrote:\s*$", re.IGNORECASE)
_REPLY_HISTORY_ORIGINAL_RE = re.compile(
    r"^\s*-{2,}\s*Original Message\s*-{2,}\s*$", re.IGNORECASE
)
_HTML_QUOTE_MARKERS = (
    re.compile(
        r"<(?:div|blockquote)\b[^>]*\bclass=[\"'][^\"']*\bgmail_quote\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"<(?:div|blockquote)\b[^>]*\bclass=[\"'][^\"']*\byahoo_quoted\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"<(?:div|blockquote)\b[^>]*\bid=[\"']divRplyFwdMsg[\"']",
        re.IGNORECASE,
    ),
    re.compile(
        r"<blockquote\b[^>]*\btype=[\"']cite[\"']", re.IGNORECASE
    ),
)


def _find_thread_quoted_history_boundary(value: str) -> int | None:
    """Locate a copied-reply tail in display text without changing source data."""
    text = str(value or "")
    if not text.strip():
        return None

    raw_lines = text.splitlines(keepends=True)
    if not raw_lines:
        raw_lines = [text]

    lines = []
    offset = 0
    for raw_line in raw_lines:
        line = raw_line.rstrip("\r\n")
        lines.append((offset, line))
        offset += len(raw_line)

    # ``splitlines(keepends=True)`` omits a final logical empty line, which is
    # irrelevant for quote detection, so no synthetic line is needed here.
    for index, (line_offset, line) in enumerate(lines):
        if (
            _REPLY_HISTORY_ON_WROTE_RE.match(line)
            or _REPLY_HISTORY_ORIGINAL_RE.match(line)
        ):
            return line_offset
        if line.lstrip().startswith(">"):
            return line_offset

        # Gmail/Outlook can soft-wrap the attribution so ``wrote:`` lands on
        # the next line (or after a separately rendered sender/address line).
        # Join only a tiny local window and require the complete attribution.
        if re.match(r"^\s*On\s+\S", line, re.IGNORECASE):
            attribution_parts = []
            for lookahead in range(index, min(index + 8, len(lines))):
                candidate = lines[lookahead][1].strip()
                if not candidate:
                    # HTML block boundaries can create empty visible lines.
                    # Ignore a small amount of that layout noise.
                    continue
                attribution_parts.append(candidate)
                attribution = " ".join(attribution_parts)
                if _REPLY_HISTORY_ON_WROTE_RE.match(attribution):
                    return line_offset
                if len(attribution_parts) >= 4 or len(attribution) > 1200:
                    break

        # Outlook commonly begins copied history with From:/Sent:/To:/Subject:.
        # Require companion headers so ordinary prose such as "From: Finance"
        # is never treated as quoted history.
        if re.match(r"^\s*From:\s*", line, re.IGNORECASE):
            nearby = [
                candidate
                for _, candidate in lines[index + 1:index + 13]
                if candidate.strip()
            ][:6]
            kinds = {
                match.group(1).casefold()
                for candidate in nearby
                for match in [
                    re.match(
                        r"^\s*(Sent|To|Cc|Subject):\s*", candidate, re.IGNORECASE
                    )
                ]
                if match
            }
            if len(kinds) >= 2:
                return line_offset

    return None


def _strip_thread_quoted_history_text(value: str) -> tuple[str, bool]:
    """Return only the authored/current reply for normal UI display.

    This is a presentation-only projection. Stored/provider content, AI input,
    draft/send behavior, task state, and security classification are untouched.
    """
    text = str(value or "")
    boundary = _find_thread_quoted_history_boundary(text)
    if boundary is None:
        return text, False

    current = text[:boundary].strip()
    if not current:
        # Quote-only messages must remain visible; otherwise hiding the quote
        # would turn a real message into a blank card.
        return text, False
    return current, True


def _html_visible_text(value: str) -> str:
    text = re.sub(r"(?is)<(?:script|style)\b.*?</(?:script|style)>", " ", str(value or ""))
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html_lib.unescape(text).replace("\xa0", " ").strip()


def _html_visible_text_with_positions(value: str) -> tuple[str, list[int]]:
    """Return approximate visible HTML text plus raw-source positions.

    The mapping lets the normal reader cut a copied ``On ... wrote:`` tail from
    provider HTML while keeping the authored part as HTML, so formatting is not
    discarded merely to hide duplicated history. This helper is display-only.
    """
    content = str(value or "")
    visible: list[str] = []
    positions: list[int] = []
    block_tag = re.compile(
        r"^</?(?:address|article|aside|blockquote|br|div|footer|h[1-6]|header|hr|"
        r"li|main|ol|p|pre|section|table|tbody|td|tfoot|th|thead|tr|ul)\b",
        re.IGNORECASE,
    )

    i = 0
    length = len(content)
    while i < length:
        if content.startswith("<!--", i):
            close = content.find("-->", i + 4)
            i = length if close < 0 else close + 3
            continue

        if content[i] == "<":
            close = content.find(">", i + 1)
            if close < 0:
                break
            tag = content[i:close + 1]
            opening = re.match(r"^<\s*(script|style)\b", tag, re.IGNORECASE)
            if opening:
                closing_match = re.search(
                    rf"</\s*{opening.group(1)}\s*>",
                    content[close + 1:],
                    re.IGNORECASE,
                )
                if closing_match:
                    i = close + 1 + closing_match.end()
                else:
                    i = length
                continue
            if block_tag.match(tag):
                visible.append("\n")
                positions.append(i)
            i = close + 1
            continue

        if content[i] == "&":
            semi = content.find(";", i + 1, min(length, i + 24))
            if semi >= 0:
                entity = content[i:semi + 1]
                decoded = html_lib.unescape(entity)
                if decoded != entity:
                    for char in decoded.replace("\xa0", " "):
                        visible.append(char)
                        positions.append(i)
                    i = semi + 1
                    continue

        visible.append(content[i])
        positions.append(i)
        i += 1

    return "".join(visible), positions


def _rewind_html_quote_boundary(content: str, boundary: int) -> int:
    """Prefer the opening block tag when the quote starts at its first text."""
    prefix = str(content or "")[:max(0, int(boundary or 0))]
    block_matches = list(
        re.finditer(
            r"<(?:blockquote|div|p|section|table|tbody|tr|td|ul|ol|li)\b[^>]*>",
            prefix,
            re.IGNORECASE,
        )
    )
    if not block_matches:
        return boundary
    candidate = block_matches[-1]
    if not _html_visible_text(prefix[candidate.end():]):
        return candidate.start()
    return boundary


def _strip_thread_quoted_history_html(value: str) -> tuple[str, bool]:
    """Trim copied reply history from normal-reader HTML only.

    Provider-specific quote containers are preferred. A visible-text boundary
    is also mapped back into the raw HTML for clients (notably Outlook/Graph)
    that flatten the original quote wrapper but leave ``On ... wrote:`` text.
    """
    content = str(value or "")
    if not content.strip():
        return content, False

    candidates = []
    for marker in _HTML_QUOTE_MARKERS:
        match = marker.search(content)
        if match:
            candidates.append(match.start())

    # Outlook often emits an <hr> before a From/Sent/To/Subject header block.
    for match in re.finditer(r"<hr\b[^>]*>", content, re.IGNORECASE):
        tail_text = _html_visible_text(content[match.end():match.end() + 5000])
        header_window = tail_text[:1200]
        has_from = bool(
            re.search(r"(?:^|\s)From:\s*", header_window, re.IGNORECASE)
        )
        companion_count = sum(
            bool(re.search(rf"(?:^|\s){label}:\s*", header_window, re.IGNORECASE))
            for label in ("Sent", "To", "Cc", "Subject")
        )
        if has_from and companion_count >= 2:
            candidates.append(match.start())
            break

    visible_text, raw_positions = _html_visible_text_with_positions(content)
    visible_boundary = _find_thread_quoted_history_boundary(visible_text)
    if visible_boundary is not None and visible_boundary < len(raw_positions):
        raw_boundary = raw_positions[visible_boundary]
        candidates.append(_rewind_html_quote_boundary(content, raw_boundary))

    if not candidates:
        return content, False

    boundary = min(candidates)
    current = content[:boundary].rstrip()
    if not _html_visible_text(current):
        return content, False
    return current, True


def _thread_display_message(
    message: dict, *, reader_body_html: str = "", reader_had_quoted_text: bool = False
) -> dict:
    """Build a non-mutating normal-workspace view without copied history.

    This function changes only the object handed to the UI renderer. The source
    message remains intact for AI processing, reply drafting/sending, mailbox
    state, thread reconciliation, and the existing Security flow.
    """
    source = dict(message or {})
    body_text = str(source.get("body_text") or "")
    native_body_html = str(source.get("body_html") or "")
    body_html = native_body_html or str(reader_body_html or "")
    clean_text, text_stripped = _strip_thread_quoted_history_text(body_text)
    clean_html, html_stripped = _strip_thread_quoted_history_html(body_html)

    # Treat text and HTML projections independently. Gmail can expose an already
    # de-quoted body_text while body_html still contains a gmail_quote container.
    # In that case the HTML cleanup must still win so the normal UI does not
    # redisplay copied history while preserving the authored HTML formatting.
    if html_stripped:
        source["body_html"] = clean_html
    elif reader_body_html and not native_body_html and not reader_had_quoted_text:
        # Original/non-reply Outlook turn: use provider-native HTML only in UI.
        source["body_html"] = str(reader_body_html or "")

    if text_stripped:
        source["body_text"] = clean_text
        source["snippet"] = clean_text

    # If source text proves copied history but the HTML boundary is ambiguous,
    # fail closed in the display copy only.
    if (reader_had_quoted_text or text_stripped) and not html_stripped:
        source["body_html"] = ""

    return source

def _inbox_thread_display_sort_key(item: dict) -> tuple:
    """Chronologically order Inbox thread turns without changing shared thread data."""
    parsed = parse_timestamp(item.get("date"))
    uid = str(item.get("uid") or item.get("message_id") or "")
    if parsed is None:
        return (0, 0.0, uid)
    return (1, parsed.timestamp(), uid)


def _clean_meta_text(value: str) -> str:
    text = str(value or "").strip()
    return "" if text.casefold() in EMPTY_META_VALUES else text


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    # Prevent urllib from following redirects before we validate the next URL.

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _sender_avatar(sender: str):
    name, address = parseaddr(sender or "")
    label = (name or address or sender or "?").strip().strip('"')
    initial = (label[:1] or "?").upper()
    tone_index = sum(ord(ch) for ch in (sender or "")) % _AVATAR_CLASS_COUNT
    return initial, f"avatar-tone-{tone_index}"


def _sender_markup(sender: str) -> str:
    name, address = parseaddr(sender or "")
    if name and address:
        return (
            f'<span class="reader-sender-name">{html_lib.escape(name)}</span>'
            f'<span class="reader-sender-address"> &lt;{html_lib.escape(address)}&gt;</span>'
        )
    return (
        '<span class="reader-sender-name">'
        f'{html_lib.escape(address or sender or "Unknown sender")}</span>'
    )


def _address_labels(value: str) -> list[str]:
    # Parse a To/Cc header into stable human-readable recipient labels.
    raw = _clean_meta_text(value)
    if not raw:
        return []

    # Semicolon-separated recipient lists are common in Outlook exports.
    parsed = []
    seen = set()
    for name, address in getaddresses([raw.replace(";", ",")]):
        label = f"{name} <{address}>" if name and address else (address or name)
        label = str(label or "").strip()
        if not label:
            continue
        fingerprint = label.casefold()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        parsed.append(label)

    if parsed:
        return parsed

    return [part.strip() for part in re.split(r"[,;]", raw) if part.strip()]


def _collapsible_address_html(
    value: str,
    *,
    visible_count: int = 2,
    kind: str = "recipient",
) -> str:
    # Render long To/Cc recipient lists compactly without a Streamlit rerun.
    labels = _address_labels(value)
    if not labels:
        return ""

    visible_count = max(1, int(visible_count or 1))
    full_title = ", ".join(labels)
    kind_class = re.sub(r"[^a-z0-9_-]+", "-", str(kind or "recipient").casefold())

    if len(labels) <= visible_count:
        return (
            f'<span class="mailmind-address-inline is-{kind_class}" '
            f'title="{html_lib.escape(full_title, quote=True)}">'
            f'{html_lib.escape(full_title)}</span>'
        )

    preview = ", ".join(labels[:visible_count])
    remaining = len(labels) - visible_count
    items = "".join(
        f'<span class="mailmind-address-recipient">{html_lib.escape(label)}</span>'
        for label in labels
    )
    return (
        f'<details class="mailmind-address-details is-{kind_class}">'
        '<summary '
        f'title="{html_lib.escape(full_title, quote=True)}">'
        f'<span class="mailmind-address-preview">{html_lib.escape(preview)}</span>'
        f'<span class="mailmind-address-more">+{remaining} more</span>'
        '<span class="mailmind-address-chevron" aria-hidden="true">⌄</span>'
        '</summary>'
        f'<div class="mailmind-address-expanded">{items}</div>'
        '</details>'
    )


def _collapsible_cc_html(value: str, *, visible_count: int = 2) -> str:
    return _collapsible_address_html(value, visible_count=visible_count, kind="cc")


def _collapsible_to_html(value: str, *, visible_count: int = 2) -> str:
    return _collapsible_address_html(value, visible_count=visible_count, kind="to")


def _header_meta_icon(kind: str) -> str:
    paths = {
        "from": '<circle cx="12" cy="8" r="3.1"/><path d="M5.8 19.2c.45-3.8 2.5-5.7 6.2-5.7s5.75 1.9 6.2 5.7"/>',
        "to": '<path d="M3.8 11.3 20.2 4.8l-6.6 16.4-2.25-7.25z"/><path d="m11.35 13.95 8.85-9.15"/>',
        "cc": '<circle cx="8.5" cy="8.2" r="2.6"/><circle cx="16.2" cy="8.9" r="2.15"/><path d="M3.6 19c.4-3.4 2.05-5.1 4.9-5.1s4.55 1.7 4.95 5.1"/><path d="M14 14.2c2.85-.1 4.6 1.35 5 4.15"/>',
        "date": '<rect x="4" y="5.5" width="16" height="14" rx="2.2"/><path d="M8 3.8v3.4M16 3.8v3.4M4 9.5h16"/>',
    }
    return (
        '<svg class="content-header-meta-icon" viewBox="0 0 24 24" aria-hidden="true" '
        'fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
        f'stroke-linejoin="round">{paths.get(kind, "")}</svg>'
    )


def _content_email_header_html(
    *,
    subject: str,
    sender: str,
    recipient: str = "",
    cc_value: str = "",
    date_display: str = "",
    show_subject: bool = True,
    security_category: str = "",
    security_confidence: int = 0,
) -> str:
    # Shared professional header used by Inbox and AI Summary content views.
    sender = str(sender or "").strip()
    recipient = _clean_meta_text(recipient)
    cc_value = _clean_meta_text(cc_value)
    date_display = str(date_display or "").strip() or "Unknown"
    initial, avatar_class = _sender_avatar(sender)

    rows = [
        (
            "From",
            f'<span class="content-header-mini-avatar {avatar_class}">{html_lib.escape(initial)}</span>',
            f'<span class="content-header-from-text">{_sender_markup(sender)}</span>',
        ),
    ]
    if recipient:
        rows.append(("To", _header_meta_icon("to"), _collapsible_to_html(recipient)))
    if cc_value:
        rows.append(("Cc", _header_meta_icon("cc"), _collapsible_cc_html(cc_value)))
    rows.append(("Date", _header_meta_icon("date"), html_lib.escape(date_display)))

    row_html = "".join(
        '<div class="content-header-meta-row">'
        f'<span class="content-header-meta-label">{html_lib.escape(label)}</span>'
        f'<span class="content-header-meta-icon-wrap">{middle_html}</span>'
        f'<span class="content-header-meta-value">{value_html}</span>'
        '</div>'
        for label, middle_html, value_html in rows
    )

    badge_html = security_badge(security_category, security_confidence)
    subject_html = ""
    if show_subject:
        subject_content = (
            f'<div class="content-email-subject" title="{html_lib.escape(subject, quote=True)}">'
            f'{html_lib.escape(subject)}</div>'
        )
        subject_html = (
            '<div class="content-email-subject-row">'
            f'{subject_content}{badge_html}'
            '</div>'
            if badge_html
            else subject_content
        )
    return (
        '<div class="content-email-header">'
        f'{subject_html}'
        f'<div class="content-header-meta-card">{row_html}</div>'
        '</div>'
    )


_FILE_TYPE_STYLES = {
    "pdf": ("PDF", "pdf"),
    "doc": ("DOC", "doc"), "docx": ("DOC", "doc"),
    "xls": ("XLS", "xls"), "xlsx": ("XLS", "xls"), "csv": ("CSV", "xls"),
    "ppt": ("PPT", "ppt"), "pptx": ("PPT", "ppt"),
    "zip": ("ZIP", "file"), "rar": ("RAR", "file"), "7z": ("7Z", "file"),
    "png": ("IMG", "img"), "jpg": ("IMG", "img"),
    "jpeg": ("IMG", "img"), "gif": ("IMG", "img"),
    "txt": ("TXT", "file"),
}


def _file_type_badge(filename: str):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return _FILE_TYPE_STYLES.get(ext, ((ext.upper()[:4] or "FILE"), "file"))


def _safe_download_filename(name: str, fallback: str) -> str:
    name = name or fallback
    cleaned = re.sub(r'[\\/*?:"<>|\r\n]', "_", name)
    cleaned = cleaned.encode("ascii", errors="ignore").decode("ascii").strip(" ._")
    return cleaned or fallback


def _format_file_size(size: int) -> str:
    try:
        value = float(size or 0)
    except (TypeError, ValueError):
        value = 0
    units = ["B", "KB", "MB", "GB"]
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"




def _attachment_extension(filename: str) -> str:
    name = str(filename or "")
    return name.rsplit(".", 1)[-1].casefold() if "." in name else ""


def _attachment_preview_kind(filename: str, mime: str) -> str:
    """Return a safe in-app preview family for an attachment.

    Active document formats (Office files, archives, executables, SVG, etc.) are
    deliberately not embedded. They remain downloadable from the preview dialog.
    """
    ext = _attachment_extension(filename)
    mime = str(mime or "application/octet-stream").split(";", 1)[0].strip().casefold()

    if mime == "application/pdf" or ext == "pdf":
        return "pdf"
    if mime.startswith("image/") and mime != "image/svg+xml" and ext != "svg":
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if ext in {"xlsx", "xlsm"} or mime in {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroenabled.12",
    }:
        # XLSX/XLSM are ZIP/XML containers. MailMind reads cell values only;
        # formulas/macros are never executed.
        return "xlsx"
    if ext in {"csv", "tsv"} or mime in {"text/csv", "text/tab-separated-values"}:
        return "table"
    if (
        mime.startswith("text/")
        or mime in {"application/json", "application/xml", "application/x-yaml", "application/yaml"}
        or ext in {"txt", "md", "log", "json", "xml", "yaml", "yml", "html", "htm", "css", "js", "py"}
    ):
        return "text"
    return "unsupported"


def _decode_attachment_text(file_bytes: bytes) -> str:
    sample = bytes(file_bytes or b"")[:ATTACHMENT_TEXT_PREVIEW_MAX_BYTES]
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return sample.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return sample.decode("utf-8", errors="replace")


def _xlsx_column_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in str(cell_ref or "") if ch.isalpha()).upper()
    index = 0
    for ch in letters:
        index = index * 26 + (ord(ch) - 64)
    return max(0, index - 1)


def _xlsx_column_label(index: int) -> str:
    value = max(0, int(index)) + 1
    label = ""
    while value:
        value, remainder = divmod(value - 1, 26)
        label = chr(65 + remainder) + label
    return label or "A"


def _xlsx_quick_preview(file_bytes: bytes, *, max_rows: int = 120, max_cols: int = 24):
    """Read passive cell values from the first XLSX/XLSM worksheet.

    The parser uses only ZIP/XML from the Python standard library. It does not
    execute formulas, VBA, external links, or embedded objects.
    """
    if not file_bytes:
        return [], "Sheet 1"

    with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
        names = set(archive.namelist())

        shared_strings = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.findall("{*}si"):
                shared_strings.append("".join(item.itertext()))

        sheet_name = "Sheet 1"
        if "xl/workbook.xml" in names:
            try:
                workbook_root = ET.fromstring(archive.read("xl/workbook.xml"))
                first_sheet = workbook_root.find(".//{*}sheet")
                if first_sheet is not None:
                    sheet_name = str(first_sheet.attrib.get("name") or sheet_name)
            except Exception:
                pass

        worksheet_paths = sorted(
            name for name in names
            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
        )
        if not worksheet_paths:
            return [], sheet_name

        sheet_root = ET.fromstring(archive.read(worksheet_paths[0]))
        rows = []
        for row_node in sheet_root.findall(".//{*}sheetData/{*}row"):
            values = {}
            max_seen = -1
            for cell in row_node.findall("{*}c"):
                col = _xlsx_column_index(cell.attrib.get("r", ""))
                if col >= max_cols:
                    continue
                cell_type = str(cell.attrib.get("t") or "")
                value_node = cell.find("{*}v")
                value = ""
                if cell_type == "inlineStr":
                    inline = cell.find("{*}is")
                    value = "".join(inline.itertext()) if inline is not None else ""
                elif value_node is not None:
                    raw = value_node.text or ""
                    if cell_type == "s":
                        try:
                            value = shared_strings[int(raw)]
                        except Exception:
                            value = raw
                    elif cell_type == "b":
                        value = "TRUE" if raw == "1" else "FALSE"
                    else:
                        value = raw
                values[col] = value
                max_seen = max(max_seen, col)

            width = min(max_seen + 1, max_cols)
            if width <= 0:
                row_values = []
            else:
                row_values = [values.get(i, "") for i in range(width)]
            rows.append(row_values)
            if len(rows) >= max_rows:
                break

        max_width = min(max((len(row) for row in rows), default=0), max_cols)
        normalized = [row + [""] * (max_width - len(row)) for row in rows]
        return normalized, sheet_name


def _attachment_card_markup(
    attachment: dict,
    index: int,
    *,
    previewable: bool = True,
    disabled_for_security: bool = False,
) -> str:
    filename = str(attachment.get("filename") or f"attachment_{index + 1}")
    label, badge_class = _file_type_badge(filename)
    file_bytes = attachment.get("data") or b""
    size_label = _format_file_size(attachment.get("size", len(file_bytes)))

    if disabled_for_security:
        secondary = f"{size_label} · Disabled for security"
        action_icon = (
            '<span class="attachment-security-lock" aria-hidden="true">'
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="5.5" y="10" width="13" height="10" rx="2"/>'
            '<path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/>'
            '</svg>'
            '</span>'
        )
        card_class = "attachment-card attachment-security-disabled-card"
    else:
        secondary = size_label if previewable else f"{size_label} · Preview unavailable"
        action_icon = (
            '<span class="attachment-preview-icon" aria-hidden="true">'
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/>'
            '<circle cx="12" cy="12" r="2.5"/>'
            '</svg>'
            '</span>'
            if previewable
            else '<span aria-hidden="true" class="attachment-download-icon">⇩</span>'
        )
        card_class = "attachment-card attachment-preview-card" if previewable else "attachment-card"

    return (
        f'<div class="{card_class}">'
        f'<span class="attachment-badge attachment-badge-{html_lib.escape(badge_class)}">'
        f'{html_lib.escape(label)}</span>'
        '<span class="attachment-copy">'
        f'<span class="attachment-name" title="{html_lib.escape(filename, quote=True)}">'
        f'{html_lib.escape(filename)}</span>'
        f'<span class="attachment-size">{html_lib.escape(secondary)}</span>'
        '</span>'
        f'{action_icon}'
        '</div>'
    )


@st.dialog("Attachment Preview", width="large")
def _show_attachment_preview(attachment: dict, dialog_token: str) -> None:
    filename = str(attachment.get("filename") or "attachment")
    file_bytes = attachment.get("data") or b""
    if not isinstance(file_bytes, (bytes, bytearray)):
        try:
            file_bytes = bytes(file_bytes)
        except Exception:
            file_bytes = b""
    file_bytes = bytes(file_bytes)
    mime = str(attachment.get("content_type") or "application/octet-stream")
    kind = _attachment_preview_kind(filename, mime)
    size_label = _format_file_size(attachment.get("size", len(file_bytes)))
    label, badge_class = _file_type_badge(filename)

    st.markdown(
        '<div class="attachment-preview-header">'
        f'<span class="attachment-badge attachment-badge-{html_lib.escape(badge_class)}">'
        f'{html_lib.escape(label)}</span>'
        '<span class="attachment-preview-header-copy">'
        f'<span class="attachment-preview-filename">{html_lib.escape(filename)}</span>'
        f'<span class="attachment-preview-meta">{html_lib.escape(size_label)} · '
        f'{html_lib.escape(mime.split(";", 1)[0])}</span>'
        '</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not file_bytes:
        st.markdown(
            '<div class="attachment-preview-message">'
            '<strong>Preview unavailable</strong>'
            '<span>The attachment data is not loaded yet.</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    preview_rendered = False
    if kind == "image" and len(file_bytes) <= ATTACHMENT_MEDIA_PREVIEW_MAX_BYTES:
        st.image(file_bytes, caption=filename, use_container_width=True)
        preview_rendered = True
    elif kind == "pdf" and len(file_bytes) <= ATTACHMENT_PDF_PREVIEW_MAX_BYTES:
        encoded = base64.b64encode(file_bytes).decode("ascii")
        st.markdown(
            '<div class="attachment-pdf-preview">'
            f'<iframe title="{html_lib.escape(filename, quote=True)}" '
            f'src="data:application/pdf;base64,{encoded}#toolbar=1&navpanes=0" '
            'loading="lazy"></iframe>'
            '</div>',
            unsafe_allow_html=True,
        )
        preview_rendered = True
    elif kind == "audio" and len(file_bytes) <= ATTACHMENT_MEDIA_PREVIEW_MAX_BYTES:
        st.audio(file_bytes, format=mime.split(";", 1)[0])
        preview_rendered = True
    elif kind == "video" and len(file_bytes) <= ATTACHMENT_MEDIA_PREVIEW_MAX_BYTES:
        st.video(file_bytes, format=mime.split(";", 1)[0])
        preview_rendered = True
    elif kind == "xlsx" and len(file_bytes) <= ATTACHMENT_PDF_PREVIEW_MAX_BYTES:
        try:
            rows, sheet_name = _xlsx_quick_preview(file_bytes)
        except (zipfile.BadZipFile, ET.ParseError, KeyError, ValueError):
            rows, sheet_name = [], "Sheet 1"
        if rows:
            width = max((len(row) for row in rows), default=0)
            columns = [_xlsx_column_label(i) for i in range(width)]
            records = []
            for row_number, row in enumerate(rows, start=1):
                record = {"#": row_number}
                record.update({columns[i]: row[i] for i in range(width)})
                records.append(record)
            st.markdown(
                '<div class="attachment-sheet-preview-note">'
                f'<strong>{html_lib.escape(sheet_name)}</strong>'
                f'<span>Quick preview · first {len(rows)} rows · formulas/macros are not executed</span>'
                '</div>',
                unsafe_allow_html=True,
            )
            st.dataframe(records, hide_index=True, use_container_width=True, height=EMAIL_SPREADSHEET_PREVIEW_HEIGHT)
            preview_rendered = True
    elif kind == "table" and len(file_bytes) <= ATTACHMENT_TEXT_PREVIEW_MAX_BYTES:
        text = _decode_attachment_text(file_bytes)
        delimiter = "\t" if _attachment_extension(filename) == "tsv" or "tab-separated" in mime.casefold() else ","
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))[:201]
        except Exception:
            rows = []
        if rows:
            header = rows[0]
            body = rows[1:201]
            width = max(len(header), max((len(row) for row in body), default=0))
            header = header + [f"Column {i + 1}" for i in range(len(header), width)]
            records = []
            for row in body:
                padded = row + [""] * (width - len(row))
                records.append({str(header[i] or f"Column {i + 1}"): padded[i] for i in range(width)})
            if records:
                st.dataframe(records, hide_index=True, use_container_width=True, height=EMAIL_TABLE_PREVIEW_HEIGHT)
            else:
                st.code(text, language=None)
        else:
            st.code(text, language=None)
        preview_rendered = True
    elif kind == "text" and len(file_bytes) <= ATTACHMENT_TEXT_PREVIEW_MAX_BYTES:
        st.code(_decode_attachment_text(file_bytes), language=None, wrap_lines=True)
        preview_rendered = True

    if not preview_rendered:
        if kind == "unsupported":
            message_title = "No in-app preview for this file type"
            message_body = "Download the file, then open it with the appropriate desktop app."
        else:
            message_title = "Attachment is too large to preview here"
            message_body = "You can still download the original file below."
        st.markdown(
            '<div class="attachment-preview-message">'
            f'<strong>{html_lib.escape(message_title)}</strong>'
            f'<span>{html_lib.escape(message_body)}</span>'
            '</div>',
            unsafe_allow_html=True,
        )

    safe_download_name = _safe_download_filename(filename, "attachment")
    st.download_button(
        "Download file",
        data=file_bytes,
        file_name=safe_download_name,
        mime=mime,
        key=f"attachment_download_{dialog_token}",
        use_container_width=True,
    )


def _arm_attachment_foreground_guard() -> None:
    # Attachment expand/preview actions trigger a full Streamlit rerun. Keep the
    # mailbox/security/auto-summary timer fragments from racing that foreground
    # render and temporarily unmounting the workspace.
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)


def _render_clickable_attachment_card(attachment: dict, index: int, token: str) -> None:
    filename = str(attachment.get("filename") or f"attachment_{index + 1}")
    file_bytes = attachment.get("data") or b""
    if not isinstance(file_bytes, (bytes, bytearray)):
        try:
            file_bytes = bytes(file_bytes)
        except Exception:
            file_bytes = b""
    file_bytes = bytes(file_bytes)
    mime = str(attachment.get("content_type") or "application/octet-stream")
    kind = _attachment_preview_kind(filename, mime)

    if kind == "unsupported":
        # Unsupported-for-preview files stay fully usable: clicking the card
        # downloads the original instead of opening a modal that can only say
        # the type is unsupported. Keep this path rerun-free.
        card_key = f"attachment_download_card_{token}_{index}"
        safe_download_name = _safe_download_filename(filename, f"attachment_{index + 1}")
        with st.container(border=False, key=card_key):
            st.markdown(
                _attachment_card_markup(attachment, index, previewable=False),
                unsafe_allow_html=True,
            )
            st.download_button(
                f"Download {filename}",
                data=file_bytes,
                file_name=safe_download_name,
                mime=mime,
                key=f"attachment_direct_download_{token}_{index}",
                use_container_width=True,
                on_click="ignore",
            )
        return

    card_key = f"attachment_card_{token}_{index}"
    button_key = f"attachment_preview_{token}_{index}"
    with st.container(border=False, key=card_key):
        st.markdown(
            _attachment_card_markup(attachment, index, previewable=True),
            unsafe_allow_html=True,
        )
        if st.button(
            f"Preview {filename}",
            key=button_key,
            type="tertiary",
            use_container_width=True,
            help=f"Preview {filename}",
            on_click=_arm_attachment_foreground_guard,
        ):
            _show_attachment_preview(attachment, f"{token}_{index}")


def _render_attachment_card_grid(
    attachments: list[dict],
    token: str,
    *,
    disabled_for_security: bool = False,
) -> None:
    for row_start in range(0, len(attachments), 2):
        row = attachments[row_start: row_start + 2]
        cols = st.columns(2, gap="small")
        for offset, attachment in enumerate(row):
            with cols[offset]:
                index = row_start + offset
                if disabled_for_security:
                    # Security/Spam original-email view is deliberately display-only.
                    # Do not mount preview/download widgets over these cards.
                    st.markdown(
                        _attachment_card_markup(
                            attachment,
                            index,
                            previewable=False,
                            disabled_for_security=True,
                        ),
                        unsafe_allow_html=True,
                    )
                else:
                    _render_clickable_attachment_card(attachment, index, token)


def _remove_dark_mode_media_blocks(content: str) -> str:
    # Remove CSS dark-mode media blocks while keeping normal email CSS intact.
    result = content
    search_from = 0
    while True:
        match = re.search(r"@media\s*[^\{]*prefers-color-scheme\s*:\s*dark[^\{]*\{", result[search_from:], re.I)
        if not match:
            break
        start = search_from + match.start()
        open_brace = search_from + match.end() - 1
        depth = 0
        end = None
        for index in range(open_brace, len(result)):
            char = result[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            result = result[:start]
            break
        result = result[:start] + result[end:]
        search_from = start
    return result


def _is_public_http_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False
        return True
    except (OSError, ValueError):
        return False


@functools.lru_cache(maxsize=EMAIL_REMOTE_IMAGE_CACHE_SIZE)
def _fetch_image_as_data_uri(url: str) -> str | None:
    # Fetch a public remote image and convert it to a data URI for reliable previewing.
    current_url = html_lib.unescape(url.strip())
    opener = urllib.request.build_opener(_NoRedirectHandler())

    for _ in range(4):
        if not _is_public_http_url(current_url):
            return None

        request = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36"
                ),
                "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            },
        )

        try:
            response = opener.open(request, timeout=EMAIL_REMOTE_IMAGE_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            if error.code in {301, 302, 303, 307, 308}:
                location = error.headers.get("Location")
                if not location:
                    return None
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            return None
        except (OSError, urllib.error.URLError, TimeoutError):
            return None

        with response:
            content_type = (response.headers.get_content_type() or "").lower()
            payload = response.read(EMAIL_REMOTE_IMAGE_MAX_BYTES + 1)
            if len(payload) > EMAIL_REMOTE_IMAGE_MAX_BYTES or not payload:
                return None
            if not content_type.startswith("image/"):
                return None
            encoded = base64.b64encode(payload).decode("ascii")
            return f"data:{content_type};base64,{encoded}"

    return None


def _embed_remote_images(content: str) -> str:
    # Proxy common remote IMG sources so they render like Gmail/Outlook image proxies.
    pattern = re.compile(r"(<img\b[^>]*?\bsrc\s*=\s*)([\"'])(https?://.*?)(\2)", re.I | re.S)
    urls = []
    seen = set()
    for match in pattern.finditer(content):
        url = html_lib.unescape(match.group(3).strip())
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= EMAIL_REMOTE_IMAGE_MAX_COUNT:
            break

    if not urls:
        return content

    replacements: dict[str, str] = {}
    workers = min(8, len(urls))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_fetch_image_as_data_uri, url): url for url in urls}
        for future, url in [(future, future_map[future]) for future in future_map]:
            try:
                data_uri = future.result()
            except Exception:
                data_uri = None
            if data_uri:
                replacements[url] = data_uri

    if not replacements:
        return content

    def replace_source(match: re.Match) -> str:
        original = html_lib.unescape(match.group(3).strip())
        replacement = replacements.get(original)
        if not replacement:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}{replacement}{match.group(4)}"

    return pattern.sub(replace_source, content)


def _disable_email_links_for_security(content: str) -> str:
    """Replace clickable HTML links with display-only spans for Security view.

    Removing ``href`` alone is not strong enough for the Security workspace: an
    ``<a>`` element can still keep link styling / pointer behavior in some email
    HTML render paths. Convert anchors to inert ``<span>`` elements instead so
    there is no hyperlink element left for the browser to activate.
    """
    if not content:
        return content

    attribute_pattern = re.compile(
        r"\s+(?:(?:xlink:)?href|target|rel|download|tabindex|"
        r"action|formaction|ping)\s*=\s*"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
        re.I | re.S,
    )

    def replace_anchor(match: re.Match) -> str:
        attrs = attribute_pattern.sub("", match.group(1) or "")
        return (
            '<span' + attrs
            + ' data-mailmind-disabled-link="true" aria-disabled="true">')

    content = re.sub(r"<a\b([^>]*)>", replace_anchor, content, flags=re.I | re.S)
    content = re.sub(r"</a\s*>", "</span>", content, flags=re.I | re.S)

    # Image maps and standalone form controls can navigate without an <a> tag.
    # Security-safe view does not need those controls, so remove image-map
    # hotspots and strip all remaining navigation attributes from every tag.
    content = re.sub(r"<area\b[^>]*>", "", content, flags=re.I | re.S)
    content = attribute_pattern.sub("", content)
    return content


# Remove unsafe wrappers while preserving the original email visual formatting.
def _prepare_html_fragment(raw_html: str, *, disable_links: bool = False) -> str:
    content = (raw_html or "").strip()
    if not content:
        return ""

    if "&lt;" in content and not re.search(r"<\s*(html|body|table|div|p|style)\b", content, re.I):
        content = html_lib.unescape(content)

    content = re.sub(r"<!doctype[^>]*>", "", content, flags=re.I)
    content = re.sub(r"<script\b[^>]*>.*?</script>", "", content, flags=re.I | re.S)
    content = re.sub(r"<iframe\b[^>]*>.*?</iframe>", "", content, flags=re.I | re.S)
    content = re.sub(r"<(object|embed|form)\b[^>]*>.*?</\1>", "", content, flags=re.I | re.S)
    content = re.sub(r"<meta\b[^>]*(color-scheme|supported-color-schemes)[^>]*>", "", content, flags=re.I)
    content = re.sub(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", "", content, flags=re.I)
    content = re.sub(r"\s+on\w+\s*=\s*(['\"]).*?\1", "", content, flags=re.I | re.S)
    content = re.sub(r"\s+on\w+\s*=\s*[^\s>]+", "", content, flags=re.I)
    content = re.sub(r"(href|src)\s*=\s*(['\"])\s*javascript:.*?\2", r'\1="#"', content, flags=re.I | re.S)
    content = re.sub(r"@import\s+[^;]+;", "", content, flags=re.I)
    content = _remove_dark_mode_media_blocks(content)

    # Convert protocol-relative asset URLs so icons/images can render correctly.
    content = re.sub(r'(?i)(src|href)=("|\')//', r'\1=\2https://', content)

    styles = "".join(re.findall(r"<style\b[^>]*>.*?</style>", content, flags=re.I | re.S))
    body_match = re.search(r"<body\b[^>]*>(.*?)</body>", content, flags=re.I | re.S)
    if body_match:
        content = body_match.group(1)
    else:
        content = re.sub(r"</?(html|head|body)\b[^>]*>", "", content, flags=re.I)

    if disable_links:
        content = _disable_email_links_for_security(content)
    else:
        content = re.sub(
            r"<a\b(?![^>]*\btarget=)",
            '<a target="_blank" rel="noopener noreferrer" ',
            content,
            flags=re.I,
        )
    content = _embed_remote_images(content)
    return styles + content


_EMAIL_PREVIEW_CSS_START = "/* EMAIL_PREVIEW_IFRAME_START */"
_EMAIL_PREVIEW_CSS_END = "/* EMAIL_PREVIEW_IFRAME_END */"


@functools.lru_cache(maxsize=EMAIL_PREVIEW_CSS_CACHE_SIZE)
def _email_preview_base_css() -> str:
    css = Path(__file__).with_name("main.css").read_text(encoding="utf-8")
    start = css.find(_EMAIL_PREVIEW_CSS_START)
    end = css.find(_EMAIL_PREVIEW_CSS_END)
    if start < 0 or end < 0 or end <= start:
        return ""
    start += len(_EMAIL_PREVIEW_CSS_START)
    return css[start:end].strip()


# Build an isolated light-mode document that keeps original email dimensions.
def _build_html_document(raw_html: str, *, disable_links: bool = False) -> str:
    fragment = _prepare_html_fragment(raw_html, disable_links=disable_links)
    preview_css = _email_preview_base_css()
    preview_css_href = "data:text/css;base64," + base64.b64encode(
        preview_css.encode("utf-8")
    ).decode("ascii")
    return (
        "<!doctype html>"
        '<html class="mailmind-email-preview-document"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light only">'
        '<meta name="supported-color-schemes" content="light">'
        '<base target="_blank">'
        f'<link rel="stylesheet" href="{preview_css_href}">'
        "</head><body><div class='email-shell'><div class='email-canvas'>"
        + fragment
        + "</div></div></body></html>"
    )


def render_reader(
    message,
    height: int | None = None,
    *,
    show_header: bool = True,
    key_prefix: str = "reader",
    spam_view: bool = False,
    folder: str = "INBOX",
):
    reader_height = int(height or EMAIL_READER_HEIGHT)
    key_prefix = str(key_prefix or "reader").strip() or "reader"
    header_key = f"{key_prefix}_header"
    # Use dedicated message/attachment keys instead of the legacy
    # ``reader_content_scroll`` hooks. Older responsive CSS in this project
    # targets those legacy keys with fixed heights; isolating the Inbox body
    # here gives this layout one clean styling authority.
    viewport_key = f"{key_prefix}_viewport"
    body_key = f"{key_prefix}_message_shell"
    attachments_key = f"{key_prefix}_attachment_section"
    empty_key = f"{key_prefix}_empty_scroll"
    if not message:
        with st.container(height=reader_height, border=False, key=empty_key):
            st.markdown(
                """
                <div class="empty-state reader-empty-state">
                    <div class="reader-empty-inner">
                        <div class="reader-empty-icon" aria-hidden="true">
                            <svg viewBox="0 0 64 64" role="img">
                                <rect x="12" y="18" width="40" height="30" rx="4" fill="none" stroke="currentColor" stroke-width="3"/>
                                <path d="M14 22.5L29.3 35.2a4.2 4.2 0 0 0 5.4 0L50 22.5" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="reader-empty-title">Select an email to view its content.</div>
                        <div class="reader-empty-copy">MailMind will show the selected email preview and details here.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        return

    email_data = message["email"]
    attachments = message.get("attachments") or []
    thread_messages = list(email_data.get("thread_messages") or [])
    is_thread = len(thread_messages) > 1

    # Inbox thread cards represent a whole conversation. Keep the shared/thread
    # service payload untouched, but make the newest real turn the default
    # reader selection/header even when provider timestamps use mixed offsets.
    # Spam/Security keeps its existing reader behavior and filtering path.
    selected_email_data = email_data
    auto_scroll_latest = False
    thread_scroll_state_key = f"{key_prefix}_thread_auto_scroll_signature"
    thread_scroll_request_key = f"{key_prefix}_thread_auto_scroll_request_seq"
    if is_thread and not spam_view:
        ordered_thread_messages = sorted(
            thread_messages, key=_inbox_thread_display_sort_key
        )
        if ordered_thread_messages:
            selected_email_data = ordered_thread_messages[-1]

            # The Inbox thread stays oldest -> newest, so the latest reply can be
            # below the initial viewport. Scroll only when the selected thread (or
            # its newest turn) changes; ordinary reruns/expander clicks must not
            # keep snapping the user back to the bottom. This is reader UI state
            # only and does not mutate shared thread/Summary data.
            latest_identity = str(
                selected_email_data.get("uid")
                or selected_email_data.get("message_id")
                or selected_email_data.get("date")
                or ""
            )
            thread_identity = str(
                email_data.get("canonical_thread_id")
                or email_data.get("gmail_thread_id")
                or email_data.get("conversation_id")
                or email_data.get("thread_subject")
                or email_data.get("subject")
                or ""
            )
            thread_signature = hashlib.sha1(
                f"{thread_identity}|{latest_identity}|{len(ordered_thread_messages)}".encode(
                    "utf-8", errors="ignore"
                )
            ).hexdigest()
            if st.session_state.get(thread_scroll_state_key) != thread_signature:
                st.session_state[thread_scroll_state_key] = thread_signature
                request_seq = int(
                    st.session_state.get(thread_scroll_request_key, 0) or 0
                ) + 1
                st.session_state[thread_scroll_request_key] = request_seq
                auto_scroll_latest = True
    else:
        # Reset when leaving an Inbox thread so reopening the same conversation
        # later scrolls to its latest turn again.
        st.session_state.pop(thread_scroll_state_key, None)

    sender = selected_email_data.get("from", "")
    recipient = _clean_meta_text(selected_email_data.get("to"))
    cc_value = _clean_meta_text(selected_email_data.get("cc"))
    subject = selected_email_data.get("subject") or "(No Subject)"
    date_display = selected_email_data.get("date_display", "Unknown")
    header_html = _content_email_header_html(
        subject=subject,
        sender=sender,
        recipient=recipient,
        cc_value=cc_value,
        date_display=date_display,
        security_category=(email_data.get("security_category", "") if spam_view else ""),
        security_confidence=(email_data.get("security_confidence", 0) if spam_view else 0),
    )

    if show_header:
        with st.container(border=False, key=header_key):
            st.markdown(header_html, unsafe_allow_html=True)

    # One scrolling surface for the selected email, Gmail/Outlook style.
    # The viewport itself is transparent and content-sized for short mail; CSS
    # only caps it when the message exceeds the available screen height. The
    # white message card and HTML iframe never own vertical scrolling.
    with st.container(border=False, key=viewport_key):
        with st.container(border=False, key=body_key):
            render_reader_content(
                message,
                include_attachments=is_thread,
                attachment_key_prefix=f"{key_prefix}_thread",
                inbox_thread_oldest_first=(not spam_view),
            )

            if auto_scroll_latest:
                st.html(
                    '<template data-mailmind-reader-scroll-latest="'
                    + html_lib.escape(viewport_key, quote=True)
                    + '" data-mailmind-scroll-request="'
                    + str(st.session_state.get(thread_scroll_request_key, 0) or 0)
                    + '"></template>',
                    width="content",
                )

        # Keep standalone attachments in the same outer viewport so a long
        # message plus files still has exactly one scrollbar. In a conversation,
        # each attachment remains attached to the exact thread turn that owns it.
        if not is_thread and _collect_message_attachments(message):
            with st.container(border=False, key=attachments_key):
                render_reader_attachments(message, key_prefix=f"{key_prefix}_attachments")

def render_reader_content(
    message,
    *,
    include_attachments: bool = True,
    attachment_key_prefix: str = "reader_thread",
    disable_external_actions: bool = False,
    inbox_thread_oldest_first: bool = False,
) -> None:
    # Render the email/thread body, optionally with its attachments.
    #
    # Callers can keep attachments inside the message or render them separately.
    # The Inbox and Original Email layouts use ``include_attachments=False`` so
    # files remain a distinct section below the message body.
    if not message:
        st.markdown(
            '<div class="reader-body">(No message content)</div>',
            unsafe_allow_html=True,
        )
        return

    email_data = message.get("email") or {}
    attachments = message.get("attachments") or []
    thread_messages = list(email_data.get("thread_messages") or [])
    reader_html_by_uid = dict(email_data.get("_mailmind_ui_thread_html_by_uid") or {})
    reader_quote_by_uid = dict(email_data.get("_mailmind_ui_thread_had_quote_by_uid") or {})

    # Normal Inbox / Summary / To-Do conversation readers already render each
    # prior turn as its own card. Hide provider-copied quoted history inside the
    # newer reply so the same messages are not nested and repeated. Security
    # readers deliberately opt out: their exact message projection and existing
    # unsafe-message rules remain unchanged.
    compact_reply_display = bool(
        inbox_thread_oldest_first and not disable_external_actions
    )

    if len(thread_messages) > 1:
        if inbox_thread_oldest_first:
            # Inbox conversation view: original/oldest turn first, newest last.
            # Sort only this display copy so Summary, Unread, Spam/Security, and
            # shared thread reconciliation keep their existing data contracts.
            display_messages = sorted(
                thread_messages, key=_inbox_thread_display_sort_key
            )
        else:
            # Preserve existing behavior for non-Inbox readers.
            display_messages = list(reversed(thread_messages))

        latest_display_index = len(display_messages)
        for index, thread_message in enumerate(display_messages, 1):
            thread_uid = str(
                thread_message.get("uid") or thread_message.get("message_id") or ""
            ).strip()
            display_message = (
                _thread_display_message(
                    thread_message,
                    reader_body_html=str(reader_html_by_uid.get(thread_uid) or ""),
                    reader_had_quoted_text=bool(reader_quote_by_uid.get(thread_uid, False)),
                )
                if compact_reply_display
                else thread_message
            )
            sender_value = str(display_message.get("from") or "Unknown sender")
            sender_name, sender_address = parseaddr(sender_value)
            sender_label = sender_name or sender_address or sender_value
            sent_label = display_message.get("date_display") or "Unknown date"
            preview = " ".join(
                str(display_message.get("body_text") or display_message.get("snippet") or "")
                .strip()
                .split()
            )
            if len(preview) > 86:
                preview = preview[:83].rstrip() + "..."
            panel_label = (
                f"{sender_label}  ·  {preview or '(No message preview)'}  ·  "
                f"{sent_label}"
            )
            thread_uid = thread_uid or str(index)
            safe_token = hashlib.sha1(
                thread_uid.encode("utf-8", errors="ignore")
            ).hexdigest()[:10]

            # Thread-only nested viewport: keep the expander/title row outside
            # the scroll surface so users always know which reply they are
            # reading. Short replies remain content-sized; only long replies
            # scroll internally. Individual emails never use this container.
            with st.expander(
                panel_label,
                expanded=(
                    index == latest_display_index
                    if inbox_thread_oldest_first
                    else index == 1
                ),
            ):
                with st.container(
                    border=False,
                    key=f"thread_turn_scroll_{safe_token}",
                ):
                    # Thread rows already expose sender, message preview, and date in
                    # the expander label. Do not repeat From/To/Cc/Date inside
                    # the expanded message body. This is shared by Inbox and
                    # Spam/Security thread readers so both projections behave
                    # consistently while preserving their existing filtering.
                    _render_message(
                        display_message,
                        thread_message.get("attachments") or [],
                        include_attachments=False,
                        disable_links=disable_external_actions,
                    )
                    if include_attachments and (thread_message.get("attachments") or []):
                        with st.container(
                            border=False,
                            key=f"thread_attachment_section_{safe_token}",
                        ):
                            render_reader_attachments(
                                {
                                    "email": thread_message,
                                    "attachments": thread_message.get("attachments") or [],
                                },
                                key_prefix=f"{attachment_key_prefix}_{safe_token}",
                                disabled_for_security=disable_external_actions,
                            )
    else:
        email_uid = str(
            email_data.get("uid") or email_data.get("message_id") or ""
        ).strip()
        display_email = (
            _thread_display_message(
                email_data,
                reader_body_html=str(reader_html_by_uid.get(email_uid) or ""),
                reader_had_quoted_text=bool(reader_quote_by_uid.get(email_uid, False)),
            )
            if compact_reply_display
            else email_data
        )
        _render_message(
            display_email,
            attachments,
            include_attachments=False,
            disable_links=disable_external_actions,
        )
        if include_attachments and attachments:
            render_reader_attachments(
                {"email": email_data, "attachments": attachments},
                key_prefix=f"{attachment_key_prefix}_single",
                disabled_for_security=disable_external_actions,
            )


_RICH_EMAIL_HTML_PATTERN = re.compile(
    r"<(?:style|table|thead|tbody|tfoot|tr|td|th|img|picture|svg|video|audio|canvas)\b",
    re.I,
)
_RICH_EMAIL_LAYOUT_PATTERN = re.compile(
    r"(?:position\s*:\s*(?:fixed|absolute)|"
    r"(?:min-|max-)?height\s*:\s*(?:100(?:vh|dvh|svh|lvh|%)|[3-9]\d{2,}px)|"
    r"overflow(?:-y)?\s*:\s*(?:auto|scroll))",
    re.I,
)


def _can_render_email_html_inline(raw_html: str) -> bool:
    """Use Streamlit's sanitized inline HTML path for simple email markup.

    Plain paragraph/div/list markup does not need an iframe and therefore
    shrinks naturally with the message. Rich/table/image/layout-heavy mail
    remains isolated in ``st.iframe`` to preserve its original formatting.
    """
    content = str(raw_html or "")
    if not content.strip():
        return False
    if _RICH_EMAIL_HTML_PATTERN.search(content):
        return False
    if _RICH_EMAIL_LAYOUT_PATTERN.search(content):
        return False
    return True


def _render_message(
    email_data,
    attachments=None,
    *,
    include_attachments: bool = True,
    disable_links: bool = False,
):
    body_html = email_data.get("body_html") or ""
    body_text = email_data.get("body_text") or ""

    if body_html.strip():
        if _can_render_email_html_inline(body_html):
            fragment = _prepare_html_fragment(body_html, disable_links=disable_links)
            st.html(
                '<div class="reader-inline-email-html">' + fragment + '</div>',
                width="stretch",
            )
        else:
            document = _build_html_document(body_html, disable_links=disable_links)
            st.iframe(
                document,
                width="stretch",
                height="content",
            )
    else:
        display_text = body_text or "(No text content)"
        escaped_text = html_lib.escape(display_text)
        if disable_links:
            # Security-safe Original Email must never pass plain text through
            # Markdown. Streamlit/Markdown auto-linking turns bare URLs,
            # mailto-like text, and Markdown link syntax into live anchors even
            # when the source email has no HTML at all. Render escaped text as
            # literal HTML text instead: the URL remains visible for inspection
            # but there is no anchor element for the browser to activate.
            st.html(
                '<div class="reader-body mailmind-security-plain-text">'
                + escaped_text
                + '</div>',
                width="stretch",
            )
        else:
            st.markdown(
                '<div class="reader-body">'
                + escaped_text
                + '</div>',
                unsafe_allow_html=True,
            )

    if not include_attachments:
        return

    attachments = attachments or email_data.get("attachments") or []
    if not attachments:
        return

    st.markdown(
        '<div class="reader-section-label">'
        f'Attachments ({len(attachments)})</div>',
        unsafe_allow_html=True,
    )

    cards_html = []
    for index, attachment in enumerate(attachments):
        filename = attachment.get("filename") or f"attachment_{index + 1}"
        safe_filename_html = html_lib.escape(filename)
        safe_download_name = _safe_download_filename(filename, f"attachment_{index + 1}")
        file_bytes = attachment.get("data") or b""
        mime = attachment.get("content_type") or "application/octet-stream"
        b64 = base64.b64encode(file_bytes).decode("ascii") if file_bytes else ""
        href = f"data:{mime};base64,{b64}" if b64 else "#"
        label, badge_class = _file_type_badge(filename)
        size_label = _format_file_size(attachment.get("size", len(file_bytes)))
        cards_html.append(
            '<a '
            f'href="{href}" '
            f'download="{html_lib.escape(safe_download_name)}" '
            'class="attachment-card">'
            f'<span class="attachment-badge attachment-badge-{badge_class}">'
            f'{html_lib.escape(label)}</span>'
            '<span class="attachment-copy">'
            f'<span class="attachment-name" title="{html_lib.escape(filename, quote=True)}">{safe_filename_html}</span>'
            f'<span class="attachment-size">{html_lib.escape(size_label)}</span>'
            '</span>'
            '<span aria-hidden="true" class="attachment-download-icon">⇩</span>'
            '</a>'
        )

    st.markdown(
        '<div class="attachment-grid">'
        + ''.join(cards_html)
        + '</div>',
        unsafe_allow_html=True,
    )


def _collect_message_attachments(message) -> list[dict]:
    # Collect unique attachments represented by an email or thread.
    if not message:
        return []

    email_data = message.get("email") or {}
    candidates = list(message.get("attachments") or [])
    for thread_message in (email_data.get("thread_messages") or []):
        candidates.extend(thread_message.get("attachments") or [])

    unique = []
    seen = set()
    for attachment in candidates:
        if not isinstance(attachment, dict):
            continue
        filename = str(attachment.get("filename") or "")
        size = int(attachment.get("size") or len(attachment.get("data") or b""))
        content_id = str(attachment.get("content_id") or attachment.get("id") or "")
        fingerprint = (content_id, filename, size)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(attachment)
    return unique


def _attachment_state_token(message, key_prefix: str) -> str:
    # Return a short stable token for attachment UI state/widget keys.
    email_data = (message or {}).get("email") or {}
    identity = "|".join(
        [
            str(key_prefix or "attachments"),
            str(email_data.get("uid") or ""),
            str(email_data.get("message_id") or ""),
            str(email_data.get("subject") or ""),
        ]
    )
    return hashlib.sha1(identity.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _toggle_attachment_expanded(state_key: str) -> None:
    # View all / Show less causes a full app rerun. Treat it exactly like the
    # Inbox filter/navigation actions that already use the white-screen guard.
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
    st.session_state[state_key] = not bool(st.session_state.get(state_key, False))


def _attachment_cards_html(attachments: list[dict]) -> str:
    cards_html = []
    for index, attachment in enumerate(attachments):
        filename = attachment.get("filename") or f"attachment_{index + 1}"
        safe_filename_html = html_lib.escape(filename)
        safe_download_name = _safe_download_filename(filename, f"attachment_{index + 1}")
        file_bytes = attachment.get("data") or b""
        mime = attachment.get("content_type") or "application/octet-stream"
        b64 = base64.b64encode(file_bytes).decode("ascii") if file_bytes else ""
        href = f"data:{mime};base64,{b64}" if b64 else "#"
        label, badge_class = _file_type_badge(filename)
        size_label = _format_file_size(attachment.get("size", len(file_bytes)))
        cards_html.append(
            '<a '
            f'href="{href}" '
            f'download="{html_lib.escape(safe_download_name)}" '
            'class="attachment-card">'
            f'<span class="attachment-badge attachment-badge-{badge_class}">'
            f'{html_lib.escape(label)}</span>'
            '<span class="attachment-copy">'
            f'<span class="attachment-name" title="{html_lib.escape(filename, quote=True)}">{safe_filename_html}</span>'
            f'<span class="attachment-size">{html_lib.escape(size_label)}</span>'
            '</span>'
            '<span aria-hidden="true" class="attachment-download-icon">⇩</span>'
            '</a>'
        )
    return ''.join(cards_html)


def _attachment_preview_limit(attachments: list[dict], requested_limit: int = 4) -> int:
    # Choose a compact preview size based on filename wrapping pressure.
    #
    # Four normal files fit comfortably as two rows. When filenames are long
    # enough to make those rows much taller, preview only the first row (two
    # files) and expose the rest behind View all. This keeps the disclosure
    # control visible at 100% browser zoom without truncating filenames.
    count = len(attachments or [])
    if count <= 2:
        return count

    base_limit = min(count, max(1, int(requested_limit or 4)))
    if base_limit <= 2:
        return base_limit

    estimated_lines = []
    for attachment in (attachments or [])[:base_limit]:
        filename = str((attachment or {}).get("filename") or "attachment")
        # At the current two-column card width, roughly 40-44 mixed filename
        # characters fit on a line. Keep the estimate conservative because
        # underscores and long unbroken tokens wrap more aggressively.
        estimated_lines.append(max(1, math.ceil(len(filename) / 42)))

    if max(estimated_lines, default=1) >= 3 or sum(estimated_lines) >= 8:
        return min(2, count)
    return base_limit


def render_reader_attachments(
    message,
    *,
    key_prefix: str = "reader_attachments",
    preview_limit: int = 4,
    disabled_for_security: bool = False,
) -> int:
    # Render a compact attachment section. Attachment cards open a safe in-app
    # preview for safely renderable types. Unsupported preview types download
    # directly instead of opening a modal that cannot render them.
    attachments = _collect_message_attachments(message)
    if not attachments:
        return 0

    count = len(attachments)
    preview_limit = _attachment_preview_limit(attachments, preview_limit)
    token = _attachment_state_token(message, key_prefix)
    state_key = f"attachment_expanded_{token}"
    toggle_key = f"attachment_toggle_{token}"
    expanded = bool(st.session_state.get(state_key, False))

    attachment_help = (
        'Preview and download disabled in Security view'
        if disabled_for_security
        else 'Preview supported files · Download others'
    )
    help_class = (
        'reader-attachments-help security-attachments-disabled-help'
        if disabled_for_security
        else 'reader-attachments-help'
    )
    st.markdown(
        '<div class="reader-attachments-heading">'
        '<span class="reader-attachments-icon" aria-hidden="true">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M21.4 11.6 12 21a6 6 0 0 1-8.5-8.5l10-10a4 4 0 0 1 5.7 5.7L9.6 17.8a2 2 0 0 1-2.8-2.8l9-9"/>'
        '</svg>'
        '</span>'
        '<span class="reader-attachments-copy">'
        '<span class="reader-attachments-title">Attachments</span>'
        f'<span class="{help_class}">{html_lib.escape(attachment_help)}</span>'
        '</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    visible = attachments if expanded else attachments[:preview_limit]
    if expanded and count > preview_limit:
        with st.container(height=ATTACHMENT_LIST_SCROLL_HEIGHT, border=False, key=f"attachment_scroll_{token}"):
            _render_attachment_card_grid(visible, token, disabled_for_security=disabled_for_security)
    else:
        _render_attachment_card_grid(visible, token, disabled_for_security=disabled_for_security)

    if count > preview_limit:
        label = "Show less ↑" if expanded else f"View all {count} attachments ↓"
        st.button(
            label,
            key=toggle_key,
            type="tertiary",
            use_container_width=True,
            on_click=_toggle_attachment_expanded,
            args=(state_key,),
        )

    return count
