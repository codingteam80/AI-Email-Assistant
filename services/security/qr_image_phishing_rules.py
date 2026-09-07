from __future__ import annotations

import base64
import html
import io
import ipaddress
import re
import threading
import zipfile
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import unquote, urlparse

from .models import SecurityRuleHit


# Visual inspection is deliberately bounded. Email attachments are attacker-
# controlled input, so a detector must not turn a compressed image/PDF/DOCX
# into unbounded CPU or memory work during background Security classification.
_MAX_ATTACHMENT_BYTES = 12 * 1024 * 1024
_MAX_TOTAL_BYTES = 36 * 1024 * 1024
_MAX_IMAGE_PIXELS = 24_000_000
_MAX_VISUALS = 16
_MAX_PDF_PAGES = 6
_MAX_DOCX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_EXTRACTED_TEXT = 24_000

_IMAGE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff",
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
}
_CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}
_TRUSTED_IDENTITY_HOSTS = (
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "google.com", "googleusercontent.com", "apple.com", "icloud.com",
    "okta.com", "duosecurity.com", "dropbox.com", "adobe.com", "docusign.com",
    "github.com", "zoom.us", "slack.com", "salesforce.com",
)
_HIGH_RISK_TLDS = (
    ".invalid", ".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support",
)

_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.I)
_DATA_IMAGE_RE = re.compile(
    r"data:image/(?:png|jpe?g|webp|gif|bmp);base64,([a-z0-9+/=\s]+)", re.I
)
_ACTION_RE = re.compile(
    r"\b(?:scan|open|view|review|read|listen|play|sign[ -]?in|log[ -]?in|access|"
    r"restore|retain|keep|confirm|approve|authorize|grant|accept|complete|continue|"
    r"renew|unlock|release|reconnect|acknowledge)\b",
    re.I,
)
_SENSITIVE_CONTEXT_RE = re.compile(
    r"\b(?:account|mailbox|email|microsoft\s*365|office\s*365|google workspace|"
    r"sharepoint|onedrive|document|file|invoice|statement|payroll|benefits?|hr portal|"
    r"password|credential|identity|session|sign[ -]?in|log[ -]?in|security alert|"
    r"mfa|2fa|authentication|permission|oauth|voicemail|voice message|storage|quota)\b",
    re.I,
)
_SECRET_REQUEST_RE = re.compile(
    r"\b(?:send|share|enter|provide|submit|reply with|type)\b.{0,80}"
    r"\b(?:password|passcode|one[- ]?time code|otp|mfa code|2fa code|recovery code|"
    r"authentication code|security code)\b",
    re.I | re.S,
)
_BENIGN_VISUAL_CONTEXT_RE = re.compile(
    r"\b(?:event ticket|boarding pass|check[- ]?in pass|restaurant menu|wifi network|"
    r"wi-fi network|contact card|business card|inventory tag|asset tag|visitor badge)\b",
    re.I,
)


@dataclass(frozen=True)
class _VisualScan:
    qr_payloads: tuple[str, ...]
    extracted_text: str
    sources: tuple[str, ...]


_ocr_lock = threading.Lock()
_ocr_engine = None
_ocr_initialization_attempted = False


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _host(url: str) -> str:
    try:
        return (urlparse(str(url or "")).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _domain_matches(left: str, right: str) -> bool:
    a = str(left or "").casefold().strip(".")
    b = str(right or "").casefold().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _trusted_identity_host(host: str) -> bool:
    value = str(host or "").casefold().strip(".")
    return any(_domain_matches(value, domain) for domain in _TRUSTED_IDENTITY_HOSTS)


def _coerce_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        compact = re.sub(r"\s+", "", value)
        if compact and len(compact) <= (_MAX_ATTACHMENT_BYTES * 4 // 3 + 16):
            try:
                return base64.b64decode(compact, validate=True)
            except (ValueError, TypeError):
                return b""
    return b""


def _unique(values) -> tuple[str, ...]:
    result = []
    seen = set()
    for value in values:
        item = " ".join(str(value or "").split()).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return tuple(result)


def _get_ocr_engine():
    global _ocr_engine, _ocr_initialization_attempted
    if _ocr_initialization_attempted:
        return _ocr_engine
    with _ocr_lock:
        if _ocr_initialization_attempted:
            return _ocr_engine
        _ocr_initialization_attempted = True
        try:
            from rapidocr_onnxruntime import RapidOCR

            _ocr_engine = RapidOCR()
        except Exception:
            _ocr_engine = None
    return _ocr_engine


def _scan_image(data: bytes) -> tuple[tuple[str, ...], str]:
    if not data or len(data) > _MAX_ATTACHMENT_BYTES:
        return (), ""
    try:
        import cv2
        import numpy as np
        from PIL import Image

        with Image.open(io.BytesIO(data)) as opened:
            width, height = opened.size
            if width <= 0 or height <= 0 or width * height > _MAX_IMAGE_PIXELS:
                return (), ""
            opened.seek(0)
            image = opened.convert("RGB")
            image.thumbnail((2400, 2400))
            rgb = np.asarray(image)
        bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    except Exception:
        return (), ""

    payloads = []
    try:
        detector = cv2.QRCodeDetector()
        decoded = detector.detectAndDecodeMulti(bgr)
        if isinstance(decoded, tuple) and len(decoded) >= 2 and bool(decoded[0]):
            payloads.extend(decoded[1] or ())
        if not payloads:
            single = detector.detectAndDecode(bgr)
            if isinstance(single, tuple) and single:
                payloads.append(single[0])
        if not any(str(value or "").strip() for value in payloads):
            # Small QR codes in mobile layouts benefit from one bounded upscale.
            enlarged = cv2.resize(bgr, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
            single = detector.detectAndDecode(enlarged)
            if isinstance(single, tuple) and single:
                payloads.append(single[0])
    except Exception:
        pass

    ocr_text = ""
    engine = _get_ocr_engine()
    if engine is not None:
        try:
            with _ocr_lock:
                result = engine(rgb)
            rows = result[0] if isinstance(result, tuple) and result else result
            words = []
            for row in rows or []:
                if not isinstance(row, (list, tuple)) or len(row) < 2:
                    continue
                confidence = float(row[2]) if len(row) > 2 else 1.0
                if confidence >= 0.45:
                    words.append(str(row[1] or ""))
            ocr_text = "\n".join(words)[:_MAX_EXTRACTED_TEXT]
        except Exception:
            ocr_text = ""
    return _unique(payloads), ocr_text


def _scan_pdf(data: bytes, source: str) -> tuple[list[str], list[str], list[str]]:
    payloads, texts, sources = [], [], []
    try:
        import pymupdf as fitz

        document = fitz.open(stream=data, filetype="pdf")
    except Exception:
        return payloads, texts, sources
    try:
        for page_number in range(min(len(document), _MAX_PDF_PAGES)):
            page = document[page_number]
            try:
                page_text = str(page.get_text("text") or "")[:_MAX_EXTRACTED_TEXT]
                if page_text.strip():
                    texts.append(page_text)
            except Exception:
                pass

            # Scan embedded raster images at their original quality first.
            for image_info in list(page.get_images(full=True))[:4]:
                try:
                    extracted = document.extract_image(int(image_info[0]))
                    image_data = bytes(extracted.get("image") or b"")
                except Exception:
                    continue
                found, ocr_text = _scan_image(image_data)
                if found or ocr_text:
                    sources.append(f"{source} page {page_number + 1}")
                payloads.extend(found)
                if ocr_text:
                    texts.append(ocr_text)

            # A rendered page also catches vector QR codes and image-only pages
            # whose PDF object structure does not expose a reusable image.
            try:
                rect = page.rect
                largest = max(float(rect.width), float(rect.height), 1.0)
                scale = min(2.2, max(0.75, 2200.0 / largest))
                pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
                rendered = pixmap.tobytes("png")
                found, ocr_text = _scan_image(rendered)
                if found or ocr_text:
                    sources.append(f"{source} page {page_number + 1}")
                payloads.extend(found)
                if ocr_text:
                    texts.append(ocr_text)
            except Exception:
                pass
    finally:
        document.close()
    return payloads, texts, sources


def _xml_visible_text(data: bytes) -> str:
    values = []
    for match in re.findall(rb"<w:t(?:\s[^>]*)?>(.*?)</w:t>", data, flags=re.S):
        value = html.unescape(match.decode("utf-8", errors="ignore"))
        if value.strip():
            values.append(value)
    return " ".join(values)[:_MAX_EXTRACTED_TEXT]


def _scan_docx(data: bytes, source: str) -> tuple[list[str], list[str], list[str]]:
    payloads, texts, sources = [], [], []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = archive.infolist()
        total_size = sum(max(0, int(item.file_size)) for item in members)
        if total_size > _MAX_DOCX_UNCOMPRESSED_BYTES:
            archive.close()
            return payloads, texts, sources
    except (OSError, ValueError, zipfile.BadZipFile):
        return payloads, texts, sources

    try:
        for member in members:
            name = str(member.filename or "").replace("\\", "/").casefold()
            if name.startswith("word/") and name.endswith(".xml") and member.file_size <= 3_000_000:
                try:
                    value = _xml_visible_text(archive.read(member))
                except Exception:
                    value = ""
                if value:
                    texts.append(value)
            if not name.startswith("word/media/") or not name.endswith(_IMAGE_EXTENSIONS):
                continue
            if member.file_size <= 0 or member.file_size > _MAX_ATTACHMENT_BYTES:
                continue
            try:
                image_data = archive.read(member)
            except Exception:
                continue
            found, ocr_text = _scan_image(image_data)
            if found or ocr_text:
                sources.append(f"{source} embedded image")
            payloads.extend(found)
            if ocr_text:
                texts.append(ocr_text)
            if len(sources) >= _MAX_VISUALS:
                break
    finally:
        archive.close()
    return payloads, texts, sources


def _scan_visual_content(body_html: str, attachments) -> _VisualScan:
    payloads, texts, sources = [], [], []
    visual_count = 0
    total_bytes = 0

    for index, encoded in enumerate(_DATA_IMAGE_RE.findall(str(body_html or ""))[:4], start=1):
        try:
            data = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
        except (ValueError, TypeError):
            continue
        if len(data) > _MAX_ATTACHMENT_BYTES:
            continue
        found, ocr_text = _scan_image(data)
        if found or ocr_text:
            sources.append(f"inline image {index}")
        payloads.extend(found)
        if ocr_text:
            texts.append(ocr_text)
        visual_count += 1

    for attachment in attachments or []:
        if visual_count >= _MAX_VISUALS or total_bytes >= _MAX_TOTAL_BYTES:
            break
        filename = str(attachment.get("filename") or "attachment").strip()
        lower_name = filename.casefold()
        content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
        data = _coerce_bytes(attachment.get("data"))
        if not data or len(data) > _MAX_ATTACHMENT_BYTES:
            continue
        total_bytes += len(data)

        if content_type.startswith("image/") or lower_name.endswith(_IMAGE_EXTENSIONS):
            found, ocr_text = _scan_image(data)
            if found or ocr_text:
                sources.append(filename)
            payloads.extend(found)
            if ocr_text:
                texts.append(ocr_text)
            visual_count += 1
        elif content_type == "application/pdf" or lower_name.endswith(".pdf"):
            found, extracted, found_sources = _scan_pdf(data, filename)
            payloads.extend(found)
            texts.extend(extracted)
            sources.extend(found_sources)
            visual_count += min(_MAX_PDF_PAGES, max(1, len(found_sources)))
        elif (
            lower_name.endswith(".docx")
            or content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ):
            found, extracted, found_sources = _scan_docx(data, filename)
            payloads.extend(found)
            texts.extend(extracted)
            sources.extend(found_sources)
            visual_count += max(1, len(found_sources))

    return _VisualScan(
        qr_payloads=_unique(payloads),
        extracted_text="\n".join(texts)[:_MAX_EXTRACTED_TEXT],
        sources=_unique(sources),
    )


def _url_is_structurally_risky(url: str) -> bool:
    value = unquote(str(url or "")).strip()
    try:
        parsed = urlparse(value)
    except ValueError:
        return True
    host = (parsed.hostname or "").casefold().strip(".")
    if parsed.scheme.casefold() not in {"http", "https"} or not host:
        return False
    if parsed.username or parsed.password:
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    return bool(
        host.startswith("xn--")
        or ".xn--" in host
        or host in _SHORTENERS
        or host.endswith(_HIGH_RISK_TLDS)
    )


def evaluate_qr_image_phishing_rules(
    *, text: str, sender: str, body_html: str, attachments, authentication_failures: int,
) -> list[SecurityRuleHit]:
    """Detect credential/action lures hidden in QR or image-only content.

    The rule requires visual phishing intent plus an untrusted destination (or a
    direct authentication-secret request). Merely containing a QR code is never
    enough: event tickets, Wi-Fi codes, inventory tags, and first-party identity
    enrollment are expected legitimate uses.
    """
    scan = _scan_visual_content(body_html, attachments)
    if not scan.sources:
        return []

    filenames = " ".join(str(item.get("filename") or "") for item in (attachments or []))
    combined = "\n".join((str(text or ""), filenames, scan.extracted_text))
    direct_secret_request = bool(_SECRET_REQUEST_RE.search(combined))
    lure_context = bool(_ACTION_RE.search(combined) and _SENSITIVE_CONTEXT_RE.search(combined))
    if not direct_secret_request and not lure_context:
        return []
    if _BENIGN_VISUAL_CONTEXT_RE.search(combined) and not direct_secret_request:
        return []

    qr_urls = [
        value for value in scan.qr_payloads
        if str(value or "").casefold().startswith(("http://", "https://"))
    ]
    ocr_urls = _URL_RE.findall(scan.extracted_text)
    visual_urls = list(_unique(qr_urls + ocr_urls))
    sender_domain = _sender_domain(sender)

    risky_urls = [value for value in visual_urls if _url_is_structurally_risky(value)]
    mismatched_urls = [
        value for value in visual_urls
        if _host(value)
        and not _domain_matches(_host(value), sender_domain)
        and not (_trusted_identity_host(_host(value)) and authentication_failures <= 0)
    ]
    free_mail_mismatch = bool(sender_domain in _CONSUMER_MAIL_DOMAINS and mismatched_urls)

    # A direct request to disclose an authentication secret is phishing even if
    # the picture contains no clickable/QR destination.
    if direct_secret_request:
        reason = "Image-only content requests an authentication secret"
    elif risky_urls:
        reason = "QR or image-only phishing lure directs to a structurally risky destination"
    elif authentication_failures > 0 and mismatched_urls:
        reason = "Failed-authentication visual lure directs to a different destination domain"
    elif free_mail_mismatch:
        reason = "Visual account-access lure from consumer mail directs to an unrelated destination"
    elif qr_urls and mismatched_urls:
        # A QR hides the destination from ordinary mail link inspection. With a
        # concrete account/security action, that concealment plus an unrelated
        # destination is sufficient for the deterministic safety floor.
        reason = "QR phishing lure hides an unrelated account-access destination"
    elif ocr_urls and mismatched_urls:
        reason = "Image-only phishing lure contains an unrelated account-access destination"
    else:
        return []

    source_summary = ", ".join(scan.sources[:3])
    if source_summary:
        reason = f"{reason} ({source_summary})"
    return [SecurityRuleHit(
        rule_id="phishing.qr_image.visual_credential_lure",
        points=100,
        reason=reason,
        categories=("Phishing",),
        strong_flag="qr-image-phishing-lure",
    )]
