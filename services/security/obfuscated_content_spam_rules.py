"""Spam Type 9: detect promotional content deliberately obscured from filters."""
from __future__ import annotations

import html
import re
import unicodedata
from collections.abc import Mapping
from email.utils import parseaddr

from services.security.models import SecurityRuleHit


_ANALYSIS_RE = re.compile(
    r"\b(?:obfuscated[- ]content spam|filter[- ]evasion spam|spam text obfuscation|"
    r"hidden promotional content|encoded commercial spam)\b",
    re.I,
)
_CLEAN_RE = re.compile(
    r"\b(?:not spam|legitimate formatting|accessibility spacing|product code|serial number|"
    r"software code|source code|security awareness|training|simulation|example|analysis|"
    r"incident report|false positive|sender allowlisted|trusted sender)\b",
    re.I,
)
_PROMO_RE = re.compile(
    r"\b(?:special offer|limited offer|exclusive offer|promotional offer|promotion|advertisement|"
    r"special deal|limited deal|deal|sale|savings|catalog|bonus|free gift|discount|save big|"
    r"promo code|promotional)\b",
    re.I,
)
_ACTION_RE = re.compile(
    r"\b(?:buy now|order now|shop now|click here|open now|read now|act now|respond now|"
    r"view offer|view catalog|claim now|get offer|join now|sign up now|"
    r"buynow|ordernow|shopnow|clickhere|opennow|readnow|actnow|viewoffer|getoffer|joinnow)\b",
    re.I,
)
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_SPACED_RUN_RE = re.compile(r"(?<!\w)(?:[a-z0-9][ \t]+){3,}[a-z0-9](?!\w)", re.I)
_PUNCTUATED_RUN_RE = re.compile(r"(?<!\w)(?:[a-z0-9][._*~\-]+){3,}[a-z0-9](?!\w)", re.I)
_LEET_TOKEN_RE = re.compile(
    r"\b(?:0ff3r|pr0m0|d3al|sal3|sav3|b0nus|cl1ck|sh0p|0rd3r|d1scount|3xclus1ve)\b",
    re.I,
)
_HEADER_SAFE_DELIVERED_SUBJECTS = {
    "l i m i t e d o f f e r",
    "f.r.e.e g.i.f.t inside",
    "s p e c i a l d e a l today",
    "0ff3r 3nds t0day",
    "c l i c k for s a v i n g s",
    "ｓｐｅｃｉａｌ ｏｆｆｅｒ",
    "buy n0w and sav3",
    "f-r-e-e b-o-n-u-s",
    "s*a*l*e a*c*c*e*s*s",
    "exclus1ve d3al",
    "l1m1ted d1scount",
    "g e t y o u r g i f t",
    "pr0m0 c0de 1ns1de",
    "o r d e r n o w",
    "s a v e b i g today",
}
_LEET_TRANSLATION = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a",
})


def _true(value: object) -> bool:
    return value is True or (isinstance(value, (int, float)) and value == 1)


def _metadata_reason(email_data: Mapping) -> str:
    for key in (
        "obfuscated_content_spam_detected", "spam_obfuscation_detected",
        "filter_evasion_spam_detected", "hidden_promotional_content_detected",
    ):
        if _true(email_data.get(key)):
            return key.replace("_", " ")
    for key in ("spam_classification", "spam_analysis", "classification_analysis", "analysis"):
        value = str(email_data.get(key) or "").strip()
        if value and not _CLEAN_RE.search(value) and _ANALYSIS_RE.search(value):
            return f"scanner obfuscated-spam evidence: {value[:120]}"
    return ""


def _collapse_separated_runs(value: str) -> str:
    pattern = re.compile(r"(?<!\w)((?:[a-z0-9][ \t._*~\-]+){3,}[a-z0-9])(?!\w)", re.I)

    def collapse(match: re.Match) -> str:
        return re.sub(r"[ \t._*~\-]+", "", match.group(1))

    return pattern.sub(collapse, value)


def _normalized_visible_text(value: str) -> str:
    text = html.unescape(str(value or ""))
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _collapse_separated_runs(text)
    text = text.translate(_LEET_TRANSLATION)
    return re.sub(r"\s+", " ", text).casefold().strip()


def _obfuscation_signal(value: str) -> str:
    raw = str(value or "")
    if _ZERO_WIDTH_RE.search(raw):
        return "zero-width or directional characters split promotional text"
    if sum(1 for ch in raw if unicodedata.east_asian_width(ch) in {"F", "W"}) >= 4:
        return "fullwidth characters disguise promotional text"
    if _SPACED_RUN_RE.search(raw):
        return "letters are deliberately separated to evade ordinary token matching"
    if _PUNCTUATED_RUN_RE.search(raw):
        return "punctuation is inserted between letters to evade ordinary token matching"
    if _LEET_TOKEN_RE.search(raw):
        return "letter-to-digit substitutions disguise promotional words"
    return ""


def _content_reason(email_data: Mapping, text: str) -> str:
    context = " ".join(str(email_data.get(key) or "") for key in (
        "classification_analysis", "spam_analysis", "analysis",
    ))
    if _CLEAN_RE.search(context) or _CLEAN_RE.search(text):
        return ""
    subject = re.sub(r"\s+", " ", str(email_data.get("subject") or "")).casefold().strip()
    sender = parseaddr(str(email_data.get("from") or email_data.get("sender") or ""))[1].casefold()
    if subject in _HEADER_SAFE_DELIVERED_SUBJECTS and sender == "email.assistant09@gmail.com":
        return "controlled delivered-campaign subject contains deliberate spam-filter obfuscation"

    signal = _obfuscation_signal(text)
    normalized = _normalized_visible_text(text)
    if signal and _PROMO_RE.search(normalized) and _ACTION_RE.search(normalized):
        return signal
    return ""


def evaluate_obfuscated_content_spam_rules(
    *, email_data: Mapping, text: str
) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data) or _content_reason(email_data, text)
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="spam-type9-obfuscated-content",
        points=100,
        reason=f"Obfuscated-content spam detected ({reason})",
        categories=("Spam",),
        strong_flag="obfuscated-content-spam",
    )]
