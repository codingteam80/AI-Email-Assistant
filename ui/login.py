# Full-page login UI for the universal IMAP sign-in flow.
#
# The existing provider detection, authentication, and saved-session logic are
# preserved. Presentation and browser-input behavior are handled here.

import html
import streamlit as st

from controllers.microsoft_auth_controller import (
    consume_microsoft_redirect_url,
    process_microsoft_callback,
    start_microsoft_login,
)
from email_handler.provider_detect import detect_provider
from services.auth_service import is_valid_email_address, login
from services.network_status_service import (
    is_network_error,
    mark_provider_connection_issue,
    mark_provider_connection_ok,
    provider_error_message,
)
from storage.session_store import create_session
from ui.markup import login_brand


def _render_login_dom_helpers(
    suppress_autofill: bool,
    has_email_error: bool,
    has_auth_error: bool,
) -> None:
    # Emit configuration only. Browser behavior lives in ui/main.js.
    st.html(
        (
            '<template data-mailmind-login-helper '
            f'data-suppress-autofill="{str(bool(suppress_autofill)).lower()}" '
            f'data-has-email-error="{str(bool(has_email_error)).lower()}" '
            f'data-has-auth-error="{str(bool(has_auth_error)).lower()}"></template>'
        ),
        width="content",
    )


def render_loading_page(
    title: str = "Signing you in",
    subtitle: str = "Please wait while we connect to your mailbox.",
    target=None,
) -> None:
    # Render a self-contained fixed overlay during login and inbox setup.

    loading_html = f"""
<div role="status" aria-live="polite" class="login-loading-overlay">
  <div class="login-loading-card">
    <div class="login-loading-brand-row">
      <svg viewBox="0 0 72 72" aria-hidden="true" class="login-loading-logo">
        <defs>
          <linearGradient id="mailMindLoadingGradient" x1="9" y1="10" x2="64" y2="65" gradientUnits="userSpaceOnUse">
            <stop stop-color="#3A5674"></stop>
            <stop offset="1" stop-color="#28425B"></stop>
          </linearGradient>
        </defs>
        <path d="M14 17.5C10.96 17.5 8.5 19.96 8.5 23V49C8.5 52.04 10.96 54.5 14 54.5H25.5L36 44.5L46.5 54.5H58C61.04 54.5 63.5 52.04 63.5 49V23C63.5 19.96 61.04 17.5 58 17.5H47.5L36 28L24.5 17.5H14Z" fill="none" stroke="url(#mailMindLoadingGradient)" stroke-width="5.2" stroke-linejoin="round"></path>
        <path d="M9.5 23L31.7 42.2C34.15 44.32 37.85 44.32 40.3 42.2L62.5 23" fill="none" stroke="url(#mailMindLoadingGradient)" stroke-width="5.2" stroke-linecap="round" stroke-linejoin="round"></path>
      </svg>
      <div class="login-loading-brand-name">MailMind <span class="login-loading-brand-accent">AI</span></div>
    </div>
    <div class="login-loading-tagline">AI-Assisted Inbox &amp; Task Management</div>
    <div class="login-loading-content">
      <div aria-hidden="true" class="login-loading-spinner"></div>
      <div class="login-loading-title">{html.escape(title)}</div>
      <div class="login-loading-subtitle">{html.escape(subtitle)}</div>
    </div>
  </div>
</div>
"""
    renderer = target if target is not None else st
    renderer.markdown(loading_html.strip(), unsafe_allow_html=True)


def _visible_auth_error(result: dict) -> str:
    # Convert a technical IMAP failure into a stable user-facing message.
    raw_error = str(result.get("error", ""))
    lowered_error = raw_error.lower()
    if "outlook.com requires oauth2" in lowered_error:
        return "Outlook.com requires the Continue with Microsoft button."
    if is_network_error(raw_error):
        return provider_error_message(raw_error, action="login")
    if any(token in lowered_error for token in (
        "authenticationfailed",
        "invalid credentials",
        "login failed",
        "authenticate",
        "app password",
    )):
        return "Couldn't sign in. Check your email address and app password."
    return "Couldn't connect to the email server. Please try again."


def _set_form_error(slot, message: str, css_class: str) -> None:
    # Update a fixed error slot without relying on another browser refresh.
    if message:
        slot.markdown(
            f'<p class="{css_class}">{html.escape(message)}</p>',
            unsafe_allow_html=True,
        )
    else:
        slot.empty()


def _queue_login_submit(email_address: str, password: str) -> bool:
    # Validate the visible form, then switch to a loading-only rerun.
    email_address = (email_address or "").strip()
    password = password or ""

    st.session_state.login_error = ""
    st.session_state.login_email_error = ""
    st.session_state.microsoft_login_error = ""

    if not is_valid_email_address(email_address):
        st.session_state.login_email_error = (
            "Enter a complete email address, such as name@example.com."
        )
        return False

    if not password:
        st.session_state.login_error = "Enter your password to continue."
        return False

    # Snapshot exactly what the user submitted. Authentication happens on the
    # next rerun, where the login form is not rendered at all.
    st.session_state.pending_login_email = email_address
    st.session_state.pending_login_password = password
    st.session_state.login_authenticating = True
    st.rerun()
    return True


def _run_pending_login() -> None:
    # Authenticate while rendering only the full-page loading screen.
    render_loading_page(
        title="Signing you in",
        subtitle="Checking your account and preparing a secure session.",
    )

    email_address = (
        st.session_state.get("pending_login_email") or ""
    ).strip()
    password = st.session_state.get("pending_login_password") or ""

    cache_key = f"detect::{email_address.lower()}"
    detection = st.session_state.get(cache_key)
    if detection is None:
        detection = detect_provider(email_address)
        st.session_state[cache_key] = detection

    if not detection.get("supported"):
        st.session_state.login_authenticating = False
        st.session_state.login_email_error = "Couldn't find this account"
        st.session_state.pending_login_password = ""
        st.rerun()

    result = login(email_address, password)
    if not result.get("success"):
        st.session_state.login_authenticating = False
        if is_network_error(result.get("error")):
            mark_provider_connection_issue(result.get("error"))
        if result.get("field") == "email":
            st.session_state.login_email_error = (
                result.get("error") or "Couldn't find this account"
            )
        else:
            st.session_state.login_error = _visible_auth_error(result)
        st.session_state.pending_login_password = ""
        st.rerun()

    token = create_session(result["client"], email_address)
    mark_provider_connection_ok()
    st.session_state.imap_client = result["client"]
    st.session_state.logged_in = True
    st.session_state.email_address = email_address
    st.session_state.session_token = token
    st.session_state.post_login_loading = True
    st.session_state.login_authenticating = False
    st.session_state.login_error = ""
    st.session_state.login_email_error = ""
    st.session_state.pending_login_email = ""
    st.session_state.pending_login_password = ""
    st.query_params["s"] = token
    st.rerun()


def render_mailbox_connection_error_page(message: str = "") -> None:
    # Persistent first-sync/provider error. Unlike a toast, this remains until
    # the user explicitly retries, so a failed login/sync can never strand the
    # app behind a permanent loading overlay.
    visible_message = str(message or "").strip() or (
        "MailMind couldn't reach your email provider. Check your internet connection and try again."
    )
    with st.container(key="login_page"):
        with st.container(key="login_card"):
            st.markdown(login_brand(), unsafe_allow_html=True)
            st.error(f"Synchronization failed\n\n{visible_message}")
            st.caption("Your saved mailbox data is unchanged. Retry after the connection is available.")
            if st.button(
                "Retry connection",
                key="initial_sync_retry_button",
                type="primary",
                use_container_width=True,
            ):
                st.session_state.initial_sync_error = ""
                st.session_state.full_sync_attempted = False
                st.session_state.inbox_loaded = False
                st.rerun()


def _render_microsoft_redirect_page() -> None:
    # Redirect the top-level browser tab to Microsoft.
    #
    # Browser redirect behavior lives in ui/main.js. This function only
    # consumes the server-side one-time redirect state and exposes the
    # trusted authorization URL as inert HTML data.
    redirect_url = consume_microsoft_redirect_url()
    if not redirect_url:
        st.session_state.microsoft_login_error = (
            "Microsoft sign-in could not be opened. Click Continue with Microsoft again."
        )
        st.rerun()

    render_loading_page(
        title="Opening Microsoft sign-in",
        subtitle="You will return here automatically after approving mailbox access.",
    )

    st.html(
        (
            '<template data-mailmind-microsoft-redirect '
            f'data-url="{html.escape(redirect_url, quote=True)}"></template>'
        ),
        width="content",
    )


def render_login_page() -> None:
    # Render login, process a Graph callback, or redirect to Microsoft.
    if process_microsoft_callback():
        return

    if st.session_state.get("microsoft_login_active"):
        _render_microsoft_redirect_page()
        return

    if st.session_state.get("login_authenticating"):
        _run_pending_login()
        return

    suppress_autofill = bool(
        st.session_state.get("suppress_login_autofill", True)
    )

    with st.container(key="login_page"):
        # A single bounded card is easier to center reliably than spacer
        # columns, which Streamlit may resize differently across viewports.
        with st.container(key="login_card"):
            st.markdown(login_brand(), unsafe_allow_html=True)

            with st.form(
                key="login_form",
                clear_on_submit=False,
                enter_to_submit=True,
                border=False,
            ):
                email_address = st.text_input(
                    "Email address",
                    key="login_email",
                    placeholder="you@example.com",
                    autocomplete="off",
                )
                email_error_slot = st.empty()

                password = st.text_input(
                    "Password",
                    type="password",
                    key="login_password",
                    placeholder="App password or account password",
                    autocomplete=(
                        "new-password"
                        if suppress_autofill
                        else "current-password"
                    ),
                )
                auth_error_slot = st.empty()

                st.markdown(
                    '<p class="login-enter-hint">Press Enter to login</p>',
                    unsafe_allow_html=True,
                )

                login_clicked = st.form_submit_button(
                    "Login",
                    key="login_button",
                    type="primary",
                    use_container_width=True,
                )

            if login_clicked:
                _queue_login_submit(email_address, password)

            st.markdown(
                '<div class="login-or-divider"><span>or</span></div>',
                unsafe_allow_html=True,
            )

            microsoft_clicked = st.button(
                "Continue with Microsoft",
                key="microsoft_login_button",
                type="primary",
                use_container_width=True,
            )
            if microsoft_clicked:
                if start_microsoft_login():
                    st.rerun()

            microsoft_error = st.session_state.get(
                "microsoft_login_error", ""
            )
            if microsoft_error:
                st.markdown(
                    f'<p class="login-auth-inline-error">{html.escape(microsoft_error)}</p>',
                    unsafe_allow_html=True,
                )

            st.markdown(
                """
                <p class="login-help-text">
                    Outlook/Hotmail accounts must use <strong>Continue with Microsoft</strong>.<br class="desktop-break" />
                    Gmail, Yahoo, and some other providers may require a generated<br class="desktop-break" />
                    <strong>app password</strong> when 2-factor authentication is enabled.
                </p>
                """,
                unsafe_allow_html=True,
            )

            email_error = st.session_state.get("login_email_error", "")
            auth_error = st.session_state.get("login_error", "")
            _set_form_error(
                email_error_slot,
                email_error,
                "login-email-inline-error",
            )
            _set_form_error(
                auth_error_slot,
                auth_error,
                "login-auth-inline-error",
            )

            _render_login_dom_helpers(
                suppress_autofill,
                bool(email_error),
                bool(auth_error),
            )
