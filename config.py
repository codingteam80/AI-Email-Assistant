# Central configuration for the AI Email Assistant.

import os
from pathlib import Path

from dotenv import load_dotenv


# Load .env from the same folder as this config.py file.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# Known IMAP providers used before live autodetection.
KNOWN_PROVIDERS = {
    "gmail.com":   {"server": "imap.gmail.com",        "port": 993},
    "outlook.com": {"server": "outlook.office365.com", "port": 993},
    "hotmail.com": {"server": "outlook.office365.com", "port": 993},
    "yahoo.com":   {"server": "imap.mail.yahoo.com",   "port": 993},
}


# App settings.
MAX_EMAILS_FETCH = 10

# Bound provider network operations so login/sync/send failures return control
# to the UI instead of leaving a permanent loading screen.
MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS = 15
# Microsoft callback includes token exchange plus initial Graph mailbox verification,
# so allow a larger bounded window than an individual provider request.
MICROSOFT_LOGIN_NETWORK_TIMEOUT_SECONDS = 45

# Auto Batch uses one fixed collection window. The mailbox monitor polls every
# 10 seconds, so 12 seconds still allows one more nearby-mail detection cycle
# with a small safety margin while reducing the visible wait.
AUTO_BATCH_WAIT_SECONDS = 12


# Mailbox/background scheduling and provider discovery.
MAILBOX_POLL_SECONDS = 10.0
MAILBOX_RECONCILE_SECONDS = 300.0
MAILBOX_SYNC_PAGE_SIZE = 250
SECURITY_CATCHUP_BATCH_SIZE = 1
SECURITY_CATCHUP_COOLDOWN_SECONDS = 2.5
NEW_MAIL_SECURITY_RETRY_SECONDS = 2.0
AUTO_SUMMARY_SECURITY_WAIT_SECONDS = 2.0
SECURITY_LLM_LOCK_TIMEOUT_SECONDS = 0.10
PROVIDER_DETECTION_CONNECT_TIMEOUT_SECONDS = 4
TODO_TITLE_BATCH_SIZE = 10
DISPLAY_TIMEZONE_CACHE_SIZE = 8
ATTACHMENT_POLICY_CACHE_SIZE = 1
EMAIL_REMOTE_IMAGE_CACHE_SIZE = 512
EMAIL_PREVIEW_CSS_CACHE_SIZE = 1

# Streamlit interaction timing. Values are intentionally unchanged; centralizing
# them only removes duplicated tuning constants from UI modules.
UI_FOREGROUND_SETTLE_SECONDS = 2.5
UI_DEBOUNCE_FAST_SECONDS = 0.20
UI_DEBOUNCE_FILTER_SECONDS = 0.28
UI_DEBOUNCE_DEFAULT_SECONDS = 0.30
UI_DEBOUNCE_REFRESH_SECONDS = 0.35
UI_DEBOUNCE_PAGINATION_SECONDS = 0.65
UI_DEBOUNCE_TODO_STATUS_SECONDS = 0.85
UI_GLOBAL_DEBOUNCE_CAP_SECONDS = 0.28
LOGOUT_HANDOFF_MIN_VISIBLE_SECONDS = 0.25

# Timed fragment intervals.
SECURITY_CATCHUP_FRAGMENT_SECONDS = 1.5
NEW_MAIL_SECURITY_FRAGMENT_SECONDS = 0.75
MAILBOX_MONITOR_FRAGMENT_SECONDS = 5.0
AUTO_SUMMARY_MONITOR_FRAGMENT_SECONDS = 1.0
SUMMARY_GENERATION_FRAGMENT_SECONDS = 1.0
DRAFT_GENERATION_FRAGMENT_SECONDS = 0.5

# UI pagination, list sizing, and preview limits.
APP_WORKSPACE_HEIGHT = 700
INBOX_LIST_HEIGHT = 820
SUMMARY_LIST_HEIGHT = 820
SUMMARY_PAGE_SIZE = 10
TODO_PAGE_SIZE = 10
SUMMARY_KEY_POINTS_PREVIEW_LIMIT = 5
SUMMARY_DEADLINES_PREVIEW_LIMIT = 3
SUMMARY_ACTION_ITEMS_PREVIEW_LIMIT = 4
NOTIFICATION_CENTER_MAX_VISIBLE = 100
NOTIFICATION_CENTER_PREVIEW_VISIBLE = 4
NOTIFICATION_HISTORY_LIMIT = 200
NOTIFICATION_DEDUPE_WINDOW_SECONDS = 12
SECURITY_ALERT_DETAIL_LIMIT = 5

# Email reader / attachment preview resource limits.
EMAIL_READER_HEIGHT = 720
EMAIL_REMOTE_IMAGE_MAX_COUNT = 28
EMAIL_REMOTE_IMAGE_MAX_BYTES = 6 * 1024 * 1024
EMAIL_REMOTE_IMAGE_TIMEOUT_SECONDS = 4
ATTACHMENT_TEXT_PREVIEW_MAX_BYTES = 2 * 1024 * 1024
ATTACHMENT_PDF_PREVIEW_MAX_BYTES = 20 * 1024 * 1024
ATTACHMENT_MEDIA_PREVIEW_MAX_BYTES = 30 * 1024 * 1024
DRAFT_EDITOR_HEIGHT = 280
EMAIL_SPREADSHEET_PREVIEW_HEIGHT = 390
EMAIL_TABLE_PREVIEW_HEIGHT = 360
ATTACHMENT_LIST_SCROLL_HEIGHT = 176
SUMMARY_READER_EMPTY_HEIGHT = 820
SUMMARY_READER_CONTENT_HEIGHT = 720
TODO_ACTION_SCROLL_HEIGHT_DEFAULT = 208
TODO_ACTION_SCROLL_HEIGHT_WITH_DEADLINES = 228
EMAIL_DISPLAY_TIMEZONE = os.getenv("EMAIL_DISPLAY_TIMEZONE", "Asia/Manila").strip() or "Asia/Manila"

# Microsoft Graph/runtime cache settings.
MICROSOFT_AUTH_FLOW_TTL_SECONDS = 15 * 60
MICROSOFT_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
MICROSOFT_GRAPH_THREAD_CACHE_LIMIT = 12

# Diagnostics. Environment toggles remain environment-owned but are parsed here
# so runtime settings have one source of truth.
WHITE_STALE_TRACE_ENABLED = str(os.getenv("MAILMIND_WHITE_STALE_TRACE", "1") or "1").strip().casefold() not in {
    "0", "false", "off", "no",
}
WHITE_STALE_TRACE_WATCHDOG_SECONDS = 8.0
WHITE_STALE_TRACE_MAX_LOG_BYTES = 5 * 1024 * 1024
GENERATION_TRACE_ENABLED = str(os.getenv("MAILMIND_GENERATION_TRACE", "1") or "1").strip().casefold() not in {
    "0", "false", "off", "no",
}


# Local LLM settings. Install Ollama and pull the model with:
# ollama pull qwen2.5:7b
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
OLLAMA_MODEL = "qwen2.5:7b"

# Structured/local LLM runtime settings. Keep Qwen reasoning disabled for app-speed
# parity with the original MailMind behavior; JSON Schema remains the output contract.
OLLAMA_THINK = False
OLLAMA_REQUEST_TIMEOUT = 120
OLLAMA_STATUS_TIMEOUT_SECONDS = 1.5
OLLAMA_TEMPERATURE = 0.1
OLLAMA_RETRY_TEMPERATURE = 0.0

# Keep the local model resident after a request so normal Summary/Draft actions
# do not repeatedly pay Ollama's model-load cost. This does not change model output.
OLLAMA_KEEP_ALIVE = "30m"

# Print Ollama's server-side timing breakdown to the terminal while performance
# tuning is active. Timing metadata is diagnostic only and never affects output.
OLLAMA_TIMING_LOG_ENABLED = True


# Microsoft Entra ID / Microsoft Graph OAuth settings.
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "").strip()
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "").strip()
MICROSOFT_AUTHORITY = os.getenv(
    "MICROSOFT_AUTHORITY",
    "https://login.microsoftonline.com/common",
).strip()
MICROSOFT_REDIRECT_URI = os.getenv(
    "MICROSOFT_REDIRECT_URI",
    "http://localhost:8501",
).strip()

# Delegated Microsoft Graph permissions requested during sign-in.
# MSAL automatically adds the OpenID Connect and offline-access scopes it needs.
MICROSOFT_SCOPES = os.getenv(
    "MICROSOFT_SCOPES",
    "User.Read Mail.Read Mail.Send",
).split()
for required_scope in ("User.Read", "Mail.Read", "Mail.Send"):
    if required_scope not in MICROSOFT_SCOPES:
        MICROSOFT_SCOPES.append(required_scope)

# Useful for disabling the Microsoft login button until the two required
# credentials have been entered in .env.
MICROSOFT_OAUTH_CONFIGURED = bool(
    MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET
)


def get_missing_microsoft_settings() -> list[str]:
    # Return the names of required Microsoft OAuth settings that are missing.
    missing = []

    if not MICROSOFT_CLIENT_ID:
        missing.append("MICROSOFT_CLIENT_ID")

    if not MICROSOFT_CLIENT_SECRET:
        missing.append("MICROSOFT_CLIENT_SECRET")

    return missing
