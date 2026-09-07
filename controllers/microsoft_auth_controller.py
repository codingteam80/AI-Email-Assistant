# Coordinate Microsoft Graph authorization-code login for Streamlit.
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from threading import Lock
from typing import Any, Dict

import streamlit as st

from config import (
    MICROSOFT_AUTHORITY,
    MICROSOFT_CLIENT_ID,
    MICROSOFT_CLIENT_SECRET,
    MICROSOFT_REDIRECT_URI,
    MICROSOFT_SCOPES,
    MICROSOFT_LOGIN_NETWORK_TIMEOUT_SECONDS,
    MICROSOFT_AUTH_FLOW_TTL_SECONDS,
    get_missing_microsoft_settings,
)
from services.microsoft_oauth_service import (
    MicrosoftGraphTokenProvider,
    MicrosoftOAuthError,
)
from storage.session_store import create_session
from services.network_status_service import (
    is_network_error,
    mark_provider_connection_issue,
    mark_provider_connection_ok,
    provider_error_message,
)


_PENDING_FLOWS: Dict[str, Dict[str, Any]] = {}
_PENDING_FLOWS_LOCK = Lock()


def start_microsoft_login() -> bool:
    # Create an authorization-code flow and queue a same-tab redirect.
    st.session_state.microsoft_login_error = ""
    missing = get_missing_microsoft_settings()
    if missing:
        st.session_state.microsoft_login_error = (
            "Microsoft Graph OAuth is not configured. Fill these values in .env: "
            + ", ".join(missing)
        )
        return False

    try:
        provider = MicrosoftGraphTokenProvider(
            client_id=MICROSOFT_CLIENT_ID,
            client_secret=MICROSOFT_CLIENT_SECRET,
            authority=MICROSOFT_AUTHORITY,
            redirect_uri=MICROSOFT_REDIRECT_URI,
            scopes=MICROSOFT_SCOPES,
        )
        flow = provider.initiate_authorization_code_flow()
    except Exception as error:
        if is_network_error(error):
            mark_provider_connection_issue(error)
            st.session_state.microsoft_login_error = provider_error_message(error, action="login")
        else:
            st.session_state.microsoft_login_error = str(error)
        return False

    state = str(flow.get("state") or "")
    if not state:
        st.session_state.microsoft_login_error = "Microsoft did not return a login state."
        return False

    _cleanup_expired_flows()
    with _PENDING_FLOWS_LOCK:
        _PENDING_FLOWS[state] = {
            "provider": provider,
            "flow": flow,
            "created_at": time.time(),
        }

    st.session_state.microsoft_login_active = True
    st.session_state.microsoft_login_redirect_url = str(flow["auth_uri"])
    return True


def process_microsoft_callback() -> bool:
    # Complete a Microsoft callback found in Streamlit query parameters.
    auth_response = _query_params_as_dict()
    if not any(key in auth_response for key in ("code", "error")):
        return False

    state = str(auth_response.get("state") or "")
    with _PENDING_FLOWS_LOCK:
        pending = _PENDING_FLOWS.pop(state, None)

    if pending is None:
        _clear_callback_query()
        st.session_state.microsoft_login_active = False
        st.session_state.microsoft_login_redirect_url = ""
        st.session_state.microsoft_login_error = (
            "The Microsoft sign-in session expired. Click Continue with Microsoft again."
        )
        return True

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="microsoft-login")
    future = executor.submit(
        pending["provider"].complete_authorization_code_flow,
        pending["flow"],
        auth_response,
    )
    try:
        result = future.result(timeout=MICROSOFT_LOGIN_NETWORK_TIMEOUT_SECONDS)
    except FutureTimeoutError as error:
        future.cancel()
        _clear_callback_query()
        st.session_state.microsoft_login_active = False
        st.session_state.microsoft_login_redirect_url = ""
        mark_provider_connection_issue(error)
        st.session_state.microsoft_login_error = (
            "Microsoft sign-in timed out while connecting to the mailbox. "
            "Check your internet connection and try again."
        )
        return True
    except Exception as error:
        _clear_callback_query()
        st.session_state.microsoft_login_active = False
        st.session_state.microsoft_login_redirect_url = ""
        if is_network_error(error):
            mark_provider_connection_issue(error)
            st.session_state.microsoft_login_error = provider_error_message(error, action="login")
        else:
            st.session_state.microsoft_login_error = str(error)
        return True
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    email_address = result["email_address"]
    client = result["client"]
    token = create_session(client, email_address)
    mark_provider_connection_ok()

    st.session_state.imap_client = client
    st.session_state.logged_in = True
    st.session_state.email_address = email_address
    st.session_state.profile_image_url = result.get("profile_image_url", "")
    st.session_state.session_token = token
    st.session_state.post_login_loading = True
    st.session_state.login_error = ""
    st.session_state.login_email_error = ""
    st.session_state.microsoft_login_error = ""
    st.session_state.microsoft_login_active = False
    st.session_state.microsoft_login_redirect_url = ""

    st.query_params.clear()
    st.query_params["s"] = token
    st.rerun()
    return True


def cancel_microsoft_login() -> None:
    st.session_state.microsoft_login_active = False
    st.session_state.microsoft_login_redirect_url = ""
    st.session_state.microsoft_login_error = ""


def get_microsoft_redirect_url() -> str:
    return str(st.session_state.get("microsoft_login_redirect_url", "") or "")


def consume_microsoft_redirect_url() -> str:
    # Return the queued OAuth URL and leave MailMind in signed-out mode.
    #
    # Microsoft opens in the current browser tab. Clearing only the temporary
    # redirect flags before navigation means the browser Back button returns to
    # the normal MailMind login form instead of immediately redirecting to
    # Microsoft again. The server-side pending OAuth flow remains available for
    # the callback when sign-in is completed.
    redirect_url = get_microsoft_redirect_url()
    st.session_state.microsoft_login_active = False
    st.session_state.microsoft_login_redirect_url = ""
    return redirect_url


def _query_params_as_dict() -> Dict[str, str]:
    result: Dict[str, str] = {}
    for key in st.query_params:
        value = st.query_params.get(key)
        if isinstance(value, list):
            value = value[-1] if value else ""
        result[str(key)] = str(value or "")
    return result


def _clear_callback_query() -> None:
    st.query_params.clear()


def _cleanup_expired_flows() -> None:
    cutoff = time.time() - MICROSOFT_AUTH_FLOW_TTL_SECONDS
    with _PENDING_FLOWS_LOCK:
        expired = [
            state
            for state, data in _PENDING_FLOWS.items()
            if float(data.get("created_at", 0)) < cutoff
        ]
        for state in expired:
            _PENDING_FLOWS.pop(state, None)
