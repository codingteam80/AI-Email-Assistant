from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import parse_qsl, urlparse

from .models import SecurityRuleHit


_CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
}
_TRUSTED_DESTINATION_HOSTS = (
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "sharepoint.com", "onedrive.com", "windows.net", "azure.com",
    "google.com", "googleusercontent.com", "okta.com", "duosecurity.com",
    "github.com", "apple.com", "icloud.com", "auth0.com",
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
}
_HIGH_RISK_TLDS = (
    ".invalid", ".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support",
)
_IDENTITY_PARAMETER_NAMES = {
    "email", "emailaddress", "loginhint", "login_hint", "mail", "recipient",
    "uid", "upn", "user", "username",
}
_INVISIBLE_CHARACTERS = {
    "\u00ad", "\u034f", "\u061c", "\u180e", "\u200b", "\u200c", "\u200d",
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\u2066", "\u2067",
    "\u2068", "\u2069", "\ufeff",
}
_CONFUSABLES = str.maketrans({
    # Cyrillic characters commonly substituted into Latin security words.
    "а": "a", "А": "a", "в": "b", "В": "b", "е": "e", "Е": "e",
    "і": "i", "І": "i", "ј": "j", "Ј": "j", "к": "k", "К": "k",
    "м": "m", "М": "m", "н": "h", "Н": "h", "о": "o", "О": "o",
    "р": "p", "Р": "p", "с": "c", "С": "c", "т": "t", "Т": "t",
    "х": "x", "Х": "x", "у": "y", "У": "y",
    # Greek look-alikes used inside otherwise Latin tokens.
    "Α": "a", "α": "a", "Β": "b", "β": "b", "Ε": "e", "ε": "e",
    "Ι": "i", "ι": "i", "Κ": "k", "κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "ο": "o", "Ρ": "p", "ρ": "p", "Τ": "t", "τ": "t",
    "Χ": "x", "χ": "x", "Υ": "y", "υ": "y",
})

_ENGLISH_ACTION_RE = re.compile(
    r"\b(?:sign\s*in|log\s*in|authenticate|continue|confirm|approve|open|access|review|"
    r"restore|retain|release|unlock|complete|claim)\b",
    re.I,
)
_ENGLISH_SENSITIVE_RE = re.compile(
    r"\b(?:account|mailbox|email|identity|authentication|session|portal|document|file|"
    r"payroll|benefits?|invoice|statement|password|credential|mfa|2fa|sso|transcript|"
    r"digital signature|workspace)\b",
    re.I,
)

# These phrases express recipient-directed actions and sensitive resources.
# Language alone is never sufficient: callers also require unrelated link risk.
_MULTILINGUAL_ACTION_RE = re.compile(
    r"(?:"
    r"inici(?:e|ar) sesi[oó]n|acceda|accede|abra|confirme|continuar|"  # Spanish
    r"connectez[- ]vous|connexion|acc[eé]dez|ouvrez|confirmez|continuer|"  # French
    r"melden sie sich an|anmelden|[oö]ffnen sie|greifen sie zu|best[aä]tigen|"  # German
    r"inicie sess[aã]o|iniciar sess[aã]o|acesse|aceda|entrar|confirme|"  # Portuguese
    r"accedi|effettua l['’]accesso|apri|conferma|continua|"  # Italian
    r"meld u aan|inloggen|open de|bevestig|doorgaan|"  # Dutch
    r"mag[- ]?(?:sign\s*in|login)|buksan|i[- ]?access|kumpirmahin|magpatuloy|"  # Tagalog
    r"zaloguj si[eę]|otw[oó]rz|uzyskaj dost[eę]p|potwierd[zź]|kontynuuj|"  # Polish
    r"[đd][aă]ng nh[aậ]p|truy c[aậ]p|m[oở]|x[aá]c nh[aậ]n|ti[eế]p t[uụ]c|"  # Vietnamese
    r"oturum a[cç]|giri[sş] yap|eri[sş]in|a[cç][iı]n|onaylay[iı]n|"  # Turkish
    r"masuk|akses|buka|konfirmasi|lanjutkan|"  # Indonesian/Malay
    r"войдите|войти|откройте|получить доступ|подтвердите|продолжить|"  # Russian
    r"تسجيل الدخول|سجّل الدخول|ادخل|افتح|أكد|تابع|"  # Arabic
    r"登录|登入|访问|打開|打开|確認|确认|继续|繼續|"  # Chinese
    r"ログイン|サインイン|アクセス|開いて|開く|確認|続行|"  # Japanese
    r"로그인|접속|열기|확인|계속"
    r")",
    re.I,
)
_MULTILINGUAL_SENSITIVE_RE = re.compile(
    r"(?:"
    r"cuenta|correo|buz[oó]n|documento|n[oó]mina|contrase[nñ]a|"
    r"compte|messagerie|bo[iî]te aux lettres|document|paie|mot de passe|"
    r"konto|postfach|dokument|gehaltsabrechnung|passwort|"
    r"conta|caixa de correio|documento|folha de pagamento|senha|"
    r"account|casella di posta|documento|busta paga|password|"
    r"rekening|postvak|document|salaris|wachtwoord|"
    r"account|email|dokumento|payroll|hudyat|"
    r"konto|skrzynka|dokument|wynagrodzenie|has[lł]o|"
    r"t[aà]i kho[aả]n|h[oộ]p th[uư]|t[aà]i li[eệ]u|b[aả]ng l[uư][oơ]ng|m[aậ]t kh[aẩ]u|"
    r"hesap|posta kutusu|belge|bordro|parola|"
    r"akun|kotak masuk|dokumen|penggajian|kata sandi|"
    r"учетн(?:ая|ой) запись|почтовый ящик|документ|зарплат|парол|"
    r"حساب|صندوق البريد|مستند|كلمة المرور|"
    r"账户|帳戶|邮箱|郵箱|文件|文档|密碼|密码|"
    r"アカウント|メールボックス|文書|ドキュメント|給与|パスワード|"
    r"계정|사서함|문서|급여|비밀번호"
    r")",
    re.I,
)
_AUTH_PATH_RE = re.compile(
    r"/(?:auth|authenticate|authentication|login|signin|sign-in|sso|mfa|2fa|session|"
    r"account|identity|continue|confirm|access|handoff)(?:[/_.?&#=-]|$)",
    re.I,
)
_NOVEL_HANDOFF_RE = re.compile(
    r"\b(?:ownership|acknowledg(?:e|ement)|handoff|workspace|roster|attestation|"
    r"transcript|digital signature|profile continuity|access card)\b",
    re.I,
)


def _sender_domain(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold().strip()
    return address.rpartition("@")[2].strip(".")


def _domain_matches(left: str, right: str) -> bool:
    a = str(left or "").casefold().strip(".")
    b = str(right or "").casefold().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _trusted_host(host: str) -> bool:
    return any(_domain_matches(host, value) for value in _TRUSTED_DESTINATION_HOSTS)


def _host(url: str) -> str:
    try:
        return (urlparse(html.unescape(str(url or ""))).hostname or "").casefold().strip(".")
    except ValueError:
        return ""


def _mixed_script_token(value: str) -> bool:
    for token in re.findall(r"[^\W\d_]{3,}", str(value or ""), re.UNICODE):
        scripts = set()
        for character in token:
            name = unicodedata.name(character, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
        if "LATIN" in scripts and scripts.intersection({"CYRILLIC", "GREEK"}):
            return True
    return False


def _has_unicode_obfuscation(value: str) -> bool:
    raw = str(value or "")
    invisible = any(character in _INVISIBLE_CHARACTERS for character in raw)
    fullwidth_ascii = any(0xFF01 <= ord(character) <= 0xFF5E for character in raw)
    mixed_script = _mixed_script_token(raw)
    excessive_marks = sum(unicodedata.combining(character) != 0 for character in raw) >= 3
    interletter_padding = bool(
        re.search(r"(?<!\w)(?:[A-Za-z][\s._-]){4,}[A-Za-z](?!\w)", raw)
    )
    return invisible or fullwidth_ascii or mixed_script or excessive_marks or interletter_padding


def _collapse_interletter_padding(value: str) -> str:
    pattern = re.compile(r"(?<!\w)(?:[A-Za-z0-9][\s._-]){3,}[A-Za-z0-9](?!\w)")
    return pattern.sub(lambda match: re.sub(r"[\s._-]+", "", match.group(0)), value)


def _normalized_text(value: str) -> str:
    raw = html.unescape(str(value or ""))
    without_controls = "".join(
        character for character in raw
        if character not in _INVISIBLE_CHARACTERS and unicodedata.category(character) != "Cf"
    )
    compatibility = unicodedata.normalize("NFKC", without_controls)
    deconfused = compatibility.translate(_CONFUSABLES).casefold()
    deconfused = _collapse_interletter_padding(deconfused)
    return re.sub(r"\s+", " ", deconfused)


def _url_is_structurally_risky(url: str) -> bool:
    try:
        parsed = urlparse(html.unescape(str(url or "")))
    except ValueError:
        return True
    host = (parsed.hostname or "").casefold().strip(".")
    if not host:
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
        or _mixed_script_token(host)
        or host in _SHORTENERS
        or host.endswith(_HIGH_RISK_TLDS)
        or host.count("-") >= 4
        or len(host) > 55
    )


def _recipient_bound(url: str) -> bool:
    try:
        parameters = parse_qsl(urlparse(html.unescape(str(url or ""))).query, keep_blank_values=True)
    except ValueError:
        return False
    for name, value in parameters:
        normalized_name = re.sub(r"[^a-z0-9_]", "", str(name or "").casefold())
        if normalized_name in _IDENTITY_PARAMETER_NAMES and str(value or "").strip():
            return True
    return False


def evaluate_multilingual_obfuscated_rules(
    *, text: str, sender: str, urls, authentication_failures: int,
) -> list[SecurityRuleHit]:
    """Detect multilingual, Unicode-obfuscated, and novel behavioral lures.

    Non-English or Unicode text is never sufficient by itself. A hit requires a
    recipient-directed sensitive action plus an unrelated destination with
    structural, identity-binding, authentication-path, or sender-risk evidence.
    """
    raw = str(text or "")
    normalized = _normalized_text(raw)
    sender_domain = _sender_domain(sender)
    destinations = []
    for raw_url in urls or []:
        url = html.unescape(str(raw_url or "")).strip().rstrip(".,;)")
        host = _host(url)
        if not host or _trusted_host(host) or _domain_matches(host, sender_domain):
            continue
        destinations.append(url)
    if not destinations:
        return []

    multilingual_action = bool(_MULTILINGUAL_ACTION_RE.search(normalized))
    multilingual_sensitive = bool(_MULTILINGUAL_SENSITIVE_RE.search(normalized))
    english_action = bool(_ENGLISH_ACTION_RE.search(normalized))
    english_sensitive = bool(_ENGLISH_SENSITIVE_RE.search(normalized))
    unicode_obfuscation = _has_unicode_obfuscation(raw)
    novel_handoff = bool(_NOVEL_HANDOFF_RE.search(normalized))
    sensitive_action = bool(
        (multilingual_action and multilingual_sensitive)
        or (english_action and english_sensitive)
    )
    if not sensitive_action:
        return []

    risky_destination = any(_url_is_structurally_risky(url) for url in destinations)
    recipient_binding = any(_recipient_bound(url) for url in destinations)
    authentication_path = any(_AUTH_PATH_RE.search(urlparse(url).path or "") for url in destinations)
    sender_risk = bool(
        authentication_failures > 0 or sender_domain in _CONSUMER_MAIL_DOMAINS
    )

    multilingual_lure = bool(
        multilingual_action
        and multilingual_sensitive
        and (risky_destination or (recipient_binding and authentication_path) or sender_risk)
    )
    obfuscated_lure = bool(
        unicode_obfuscation
        and english_action
        and english_sensitive
        and (risky_destination or recipient_binding or authentication_path)
    )
    novel_behavioral_lure = bool(
        novel_handoff
        and english_action
        and english_sensitive
        and authentication_path
        and (risky_destination or recipient_binding)
    )
    if not (multilingual_lure or obfuscated_lure or novel_behavioral_lure):
        return []

    if unicode_obfuscation and obfuscated_lure:
        reason = "Unicode-obfuscated sensitive action directs to an unrelated identity destination"
    elif multilingual_lure:
        reason = "Multilingual sensitive-action lure directs to an unrelated risky destination"
    else:
        reason = "Novel account-access wording combines an identity handoff with a risky destination"

    return [SecurityRuleHit(
        rule_id="phishing.multilingual_obfuscated.behavioral_lure",
        points=100,
        reason=reason,
        categories=("Phishing",),
        strong_flag="multilingual-obfuscated-novel-lure",
    )]
