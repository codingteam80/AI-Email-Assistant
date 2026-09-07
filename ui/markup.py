# Reusable HTML fragments for the Streamlit UI.

import html


def section_label(text: str) -> str:
    return f'<div class="section-label">{html.escape(text)}</div>'


def sidebar_brand(title: str, tagline: str) -> str:
    return f"""
<div class="sidebar-brand-wrap">
    <div class="sidebar-brand-row">
        <div class="sidebar-brand-logo" aria-hidden="true">
            <svg viewBox="0 0 72 72" role="img" aria-label="MailMind logo">
                <defs>
                    <linearGradient id="mailMindSidebarGradient" x1="9" y1="10" x2="64" y2="65" gradientUnits="userSpaceOnUse">
                        <stop stop-color="#8CC0FF" />
                        <stop offset="1" stop-color="#F2F8FF" />
                    </linearGradient>
                </defs>
                <path d="M14 17.5C10.96 17.5 8.5 19.96 8.5 23V49C8.5 52.04 10.96 54.5 14 54.5H25.5L36 44.5L46.5 54.5H58C61.04 54.5 63.5 52.04 63.5 49V23C63.5 19.96 61.04 17.5 58 17.5H47.5L36 28L24.5 17.5H14Z" fill="none" stroke="url(#mailMindSidebarGradient)" stroke-width="5.2" stroke-linejoin="round" />
                <path d="M9.5 23L31.7 42.2C34.15 44.32 37.85 44.32 40.3 42.2L62.5 23" fill="none" stroke="url(#mailMindSidebarGradient)" stroke-width="5.2" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
        </div>
        <div>
            <div class="sidebar-brand-title">{html.escape(title)}</div>
            <div class="sidebar-brand-tagline">{tagline}</div>
        </div>
    </div>
    <div class="sidebar-divider"></div>
</div>
"""


def login_brand() -> str:
    return """
<div class="login-brand-block">
    <div class="login-brand-row">
        <svg class="login-brand-logo" viewBox="0 0 72 72" role="img" aria-label="MailMind logo">
            <defs>
                <linearGradient id="mailMindGradient" x1="9" y1="10" x2="64" y2="65" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#3A5674" />
                    <stop offset="1" stop-color="#28425B" />
                </linearGradient>
            </defs>
            <path d="M14 17.5C10.96 17.5 8.5 19.96 8.5 23V49C8.5 52.04 10.96 54.5 14 54.5H25.5L36 44.5L46.5 54.5H58C61.04 54.5 63.5 52.04 63.5 49V23C63.5 19.96 61.04 17.5 58 17.5H47.5L36 28L24.5 17.5H14Z" fill="none" stroke="url(#mailMindGradient)" stroke-width="5.2" stroke-linejoin="round" />
            <path d="M9.5 23L31.7 42.2C34.15 44.32 37.85 44.32 40.3 42.2L62.5 23" fill="none" stroke="url(#mailMindGradient)" stroke-width="5.2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="login-brand-name">MailMind <strong>AI</strong></div>
    </div>
    <div class="login-brand-tagline">AI-Assisted Inbox &amp; Task Management</div>
</div>
"""


_SECURITY_BADGE_VARIANTS = {
    "Spam": "security-spam",
    "Promotional": "security-promotional",
    "Phishing": "security-phishing",
    "Malware": "security-malware",
    "Scam / Fraud": "security-scam-fraud",
    "Impersonation": "security-impersonation",
    "Suspicious": "security-suspicious",
    "Safe / Misclassified": "security-safe-misclassified",
}


def security_badge(category: str, confidence: int = 0) -> str:
    # Render one compact security category badge. Unknown/legacy values stay
    # badge-free until the cache migration classifies them.
    category = str(category or "").strip()
    variant = _SECURITY_BADGE_VARIANTS.get(category)
    if not variant:
        return ""
    return (
        f'<span class="mail-security-badge {variant}" '
        f'title="{html.escape(category, quote=True)}">'
        f'{html.escape(category.upper())}</span>'
    )
