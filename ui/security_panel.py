import html
import re

import streamlit as st

from config import UI_FOREGROUND_SETTLE_SECONDS

from services.ui_interaction_service import arm_foreground_interaction


_CATEGORY_META = {
    "Spam": "MailMind detected stronger unwanted or bulk-email characteristics without a clear malicious threat.",
    "Promotional": "MailMind detected ordinary marketing or promotional content without stronger spam or malicious-security evidence.",
    "Phishing": "MailMind detected indicators consistent with credential or sensitive-information theft.",
    "Malware": "MailMind detected a potentially dangerous attachment, file, or payload-delivery pattern.",
    "Scam / Fraud": "MailMind detected social-engineering or financial-fraud indicators in this message.",
    "Impersonation": "MailMind detected signs that the sender may be presenting as a trusted person or organization.",
    "Suspicious": "MailMind detected meaningful warning signs, but the evidence is not strong enough for a more specific category.",
    "Safe / Misclassified": "MailMind did not find strong evidence of spam or a security threat in this message.",
}

_PROVIDER_ONLY_REASONS = {
    "the email provider placed it in spam/junk",
}


def _category_slug(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(category or "").casefold()).strip("-")


def _reason_detail(reason: str) -> str:
    text = str(reason or "").casefold()
    if "link" in text or "url" in text:
        return "A link or destination in the message contributed to the security assessment."
    if any(word in text for word in ("prize", "reward", "congratulations", "winner")):
        return "Unexpected prize or reward language is commonly used in social-engineering scams."
    if "urgent" in text or "urgency" in text:
        return "Pressure or time-sensitive wording can be used to push recipients into acting quickly."
    if "authentication" in text or "dmarc" in text or "spf" in text or "dkim" in text:
        return "Sender-authentication evidence contributed to MailMind's trust assessment."
    if "reply-to" in text or "sender domain" in text or "impersonat" in text:
        return "The apparent sender identity or reply destination does not fully align with the message identity."
    if "credential" in text or "sensitive" in text or "password" in text or "otp" in text:
        return "The message requests or references account credentials or other sensitive information."
    if "attachment" in text or "executable" in text or "payload" in text:
        return "The attachment type, filename, or payload characteristics require additional caution."
    if "promotional" in text or "marketing" in text:
        return "The message contains marketing or offer language. By itself, this does not indicate deception or a security threat."
    if "bulk" in text:
        return "The message shows characteristics commonly associated with unsolicited or bulk mail."
    if "delivery" in text or "package" in text or "shipping" in text:
        return "The message uses a delivery or package scenario that contributed to the fraud-risk assessment."
    if "financial" in text or "payment" in text or "invoice" in text or "charge" in text or "fee" in text:
        return "A payment or financial request contributed to the fraud-risk assessment."
    if "reported as spam by user" in text:
        return "This message was explicitly marked as spam by the user."
    return "This signal contributed to MailMind's final security classification."


def _classification_reasons(email_data: dict) -> list[tuple[str, str]]:
    category = str(email_data.get("security_category") or "Safe / Misclassified")

    # Safe / Misclassified is a final safe verdict. Keep weak/internal signals in
    # storage for diagnostics, but do not present them as warning reasons in the UI.
    if category == "Safe / Misclassified":
        return [
            (
                "No strong malicious indicators were found",
                "MailMind did not find enough evidence of phishing, malware, fraud, impersonation, or suspicious behavior.",
            )
        ]

    raw = str(email_data.get("spam_reason") or "")
    reasons = []
    seen = set()
    for value in raw.split(";"):
        reason = " ".join(str(value or "").strip().split())
        if not reason:
            continue
        key = reason.casefold()
        if key in _PROVIDER_ONLY_REASONS or key in seen:
            continue
        seen.add(key)
        reasons.append((reason, _reason_detail(reason)))

    if reasons:
        return reasons

    if category == "Spam":
        return [
            (
                "Unwanted-mail characteristics detected",
                "MailMind found stronger signals consistent with unsolicited or bulk email.",
            )
        ]
    if category == "Promotional":
        return [
            (
                "Marketing content detected",
                "MailMind identified ordinary promotional or offer content without stronger spam or malicious-security evidence.",
            )
        ]
    return [
        (
            f"Signals consistent with {category}",
            "MailMind identified security evidence that supports this classification.",
        )
    ]


def _shield_svg() -> str:
    return (
        '<svg viewBox="0 0 48 54" aria-hidden="true">'
        '<path d="M24 2.5 43 9.2v14.5c0 12.8-7.7 22.7-19 27.8C12.7 46.4 5 36.5 5 23.7V9.2L24 2.5Z" fill="currentColor"/>'
        '<path d="M24 14.2v16.4" stroke="white" stroke-width="4.2" stroke-linecap="round"/>'
        '<circle cx="24" cy="38.2" r="2.4" fill="white"/>'
        '</svg>'
    )


def render_security_assessment(selected_message, *, folder: str = "ALL_MAIL") -> None:
    email_data = dict((selected_message or {}).get("email") or {})
    if not email_data:
        st.markdown(
            '<div class="security-review-empty">'
            '<div class="security-review-empty-icon" aria-hidden="true">&#128737;</div>'
            '<div class="security-review-empty-title">Select an email to review its security classification.</div>'
            '<div class="security-review-empty-copy">MailMind will show the category and the signals behind its decision.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    uid = str(email_data.get("uid") or "").strip()
    category = str(email_data.get("security_category") or "Safe / Misclassified")
    summary = _CATEGORY_META.get(category, _CATEGORY_META["Suspicious"])
    slug = _category_slug(category) or "suspicious"
    reasons = _classification_reasons(email_data)

    def render_reason_items(items: list[tuple[str, str]]) -> str:
        return "".join(
            '<div class="security-review-reason">'
            '<div class="security-review-reason-icon" aria-hidden="true">!</div>'
            '<div class="security-review-reason-copy">'
            f'<div class="security-review-reason-title">{html.escape(title)}</div>'
            f'<div class="security-review-reason-detail">{html.escape(detail)}</div>'
            '</div>'
            '</div>'
            for title, detail in items
        )

    if category == "Safe / Misclassified":
        reasons_html = (
            '<div class="security-review-safe-note">'
            '<span class="security-review-safe-dot" aria-hidden="true">✓</span>'
            '<span><strong>No strong malicious indicators were found.</strong> '
            'MailMind did not find enough evidence of phishing, malware, fraud, impersonation, or suspicious behavior.</span>'
            '</div>'
        )
    else:
        visible_reasons = reasons[:3]
        visible_reasons_html = render_reason_items(visible_reasons)
        if len(reasons) > 3:
            all_reasons_html = render_reason_items(reasons)
            reasons_html = (
                '<div class="security-review-reasons">'
                '<div class="security-review-reasons-collapsed">'
                f'{visible_reasons_html}'
                '</div>'
                '<details class="security-review-more">'
                '<summary class="security-review-more-toggle">'
                f'<span class="security-review-toggle-open">View all ({len(reasons)})</span>'
                '<span class="security-review-toggle-close">Show less</span>'
                '<span class="security-review-toggle-chevron" aria-hidden="true">⌄</span>'
                '</summary>'
                '<div class="security-review-reasons-expanded">'
                f'{all_reasons_html}'
                '</div>'
                '</details>'
                '</div>'
            )
        else:
            reasons_html = (
                '<div class="security-review-reasons">'
                f'{visible_reasons_html}'
                '</div>'
            )

    provider_note = ""
    if int(email_data.get("provider_spam") or 0):
        provider_note = (
            '<div class="security-review-provider-note">'
            '<span class="security-review-provider-dot" aria-hidden="true">i</span>'
            '<span>This message is shown in the Spam workspace because your email provider placed it in Spam/Junk. '
            "Provider location does not determine MailMind's final category.</span>"
            '</div>'
        )

    st.markdown(
        f'<div class="security-review-card is-{slug}">'
        '<div class="security-review-hero">'
        f'<div class="security-review-shield">{_shield_svg()}</div>'
        '<div class="security-review-hero-copy">'
        '<div class="security-review-classification">'
        f'<span>{html.escape(category.upper())}</span>'
        '</div>'
        '</div>'
        '</div>'
        '<div class="security-review-body">'
        f'<div class="security-review-section-title">Why MailMind classified this email as {html.escape(category)}</div>'
        f'{reasons_html}'
        f'{provider_note}'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    with st.container(border=False, key="spam_security_actions"):
        action_spacer, action_col = st.columns([0.76, 0.24], gap="small")
        with action_col:
            if st.button(
                "View Email",
                icon=":material/mail:",
                key=f"spam_view_email_{uid}",
                type="secondary",
                use_container_width=True,
                disabled=not bool(uid),
            ):
                st.session_state.foreground_navigation_guard = True
                arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
                st.session_state.pop("draft_dialog_uid", None)
                st.session_state.pop("original_dialog_uid", None)
                st.session_state.spam_email_dialog_uid = uid
