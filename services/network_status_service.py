# Provider/network connection state shared by login, mailbox sync, send, and UI.
from __future__ import annotations

import socket
from typing import Any

import streamlit as st


_CONNECTED = "connected"
_ISSUE = "issue"


def _clean_error(error: Any) -> str:
    return str(error or "").strip()


def is_network_error(error: Any) -> bool:
    """Best-effort classification for transient provider/network failures."""
    if isinstance(error, (ConnectionError, TimeoutError, socket.timeout, OSError)):
        return True
    text = _clean_error(error).casefold()
    return any(
        token in text
        for token in (
            "timed out",
            "timeout",
            "could not connect",
            "could not reach",
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "name or service not known",
            "temporary failure in name resolution",
            "getaddrinfo failed",
            "remote end closed connection",
            "server disconnected",
            "failed to establish a new connection",
            "max retries exceeded",
        )
    )


def provider_error_message(error: Any, *, action: str = "connect") -> str:
    """Return concise provider-facing copy without confusing it with AI health."""
    if is_network_error(error):
        if action == "send":
            return (
                "Could not connect to your email provider. Your draft is saved. "
                "Check your internet connection and try again."
            )
        if action == "refresh":
            return (
                "MailMind couldn't reach your email provider. "
                "Check your internet connection and try again."
            )
        if action == "login":
            return (
                "Unable to connect to your email provider. "
                "Check your internet connection and try again."
            )
        return (
            "MailMind couldn't reach your email provider. "
            "Check your internet connection and try again."
        )

    detail = _clean_error(error)
    if action == "send":
        return (
            "The reply could not be sent. Your draft is saved. "
            + (detail or "Please review the account connection and try again.")
        )
    if action == "login":
        return detail or "MailMind could not open your mailbox. Please try again."
    if action == "refresh":
        return detail or "MailMind could not synchronize your mailbox. Please try again."
    return detail or "The email provider operation could not be completed."


def mark_provider_connection_issue(error: Any = "") -> bool:
    """Set provider connection state to an issue; return True on state transition."""
    previous = str(st.session_state.get("provider_connection_state") or _CONNECTED)
    st.session_state.provider_connection_state = _ISSUE
    st.session_state.provider_connection_error = _clean_error(error)
    return previous != _ISSUE


def mark_provider_connection_ok() -> bool:
    """Return provider status to Connected; return True on state transition."""
    previous = str(st.session_state.get("provider_connection_state") or _CONNECTED)
    st.session_state.provider_connection_state = _CONNECTED
    st.session_state.provider_connection_error = ""
    # A later outage may create one new background Bell alert.
    st.session_state.provider_connection_notice_active = False
    return previous != _CONNECTED


def provider_connection_status() -> tuple[str, bool]:
    state = str(st.session_state.get("provider_connection_state") or _CONNECTED)
    has_issue = state == _ISSUE
    return ("Connection issue" if has_issue else "Connected"), has_issue
