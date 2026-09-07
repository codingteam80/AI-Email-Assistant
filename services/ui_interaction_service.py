"""Small coordination helpers for foreground Streamlit interactions.

These helpers do not own any MailMind business logic. They only give user-driven
full-app reruns a short settling window so timed background fragments cannot
request another app rerun while Streamlit is still replacing the workspace DOM.
"""
from __future__ import annotations

import time

import streamlit as st

from config import (
    UI_DEBOUNCE_DEFAULT_SECONDS,
    UI_FOREGROUND_SETTLE_SECONDS,
    UI_GLOBAL_DEBOUNCE_CAP_SECONDS,
)
from services.white_stale_trace_service import trace_action



def workspace_interaction_allowed() -> bool:
    """Return False while the signed-in workspace is being torn down.

    Browser events from widgets that were mounted before Logout can arrive a
    few milliseconds after the server has already cleared the account state.
    Those stale callbacks must be inert; otherwise they can mutate fresh login
    state or schedule another rerun while Streamlit is replacing the workspace.
    """
    return bool(st.session_state.get("logged_in", False)) and not bool(
        st.session_state.get("logout_requested", False)
        or st.session_state.get("logout_in_progress", False)
    )


def workspace_callback_allowed(*allowed_workspaces: str) -> bool:
    """Reject stale callbacks that arrive after a workspace has changed.

    The original ``workspace_interaction_allowed`` remains the global login/logout
    gate. Workspace-owned widgets call this stricter helper so an Inbox widget
    cannot mutate Summary/To-Do state (and vice versa) while Streamlit is
    replacing the workspace DOM.
    """
    if not workspace_interaction_allowed():
        return False
    if not allowed_workspaces:
        return True
    current = str(st.session_state.get("active_workspace") or "inbox").strip().casefold()
    allowed = {str(name or "").strip().casefold() for name in allowed_workspaces}
    if current in allowed:
        return True
    trace_action(
        "workspace-callback-ignored",
        outcome="stale-cross-workspace",
        current_workspace=current,
        allowed_workspaces=sorted(allowed),
    )
    return False


def arm_foreground_interaction(settle_seconds: float = UI_FOREGROUND_SETTLE_SECONDS) -> None:
    """Protect the current user-triggered full-app rerun and its DOM settle window."""
    st.session_state.foreground_navigation_guard = True
    try:
        seconds = max(0.0, float(settle_seconds))
    except (TypeError, ValueError):
        seconds = UI_FOREGROUND_SETTLE_SECONDS
    until = time.time() + seconds
    current = float(st.session_state.get("foreground_ui_settle_until", 0.0) or 0.0)
    if until > current:
        st.session_state.foreground_ui_settle_until = until


def foreground_interaction_is_settling() -> bool:
    """Return True while foreground navigation should own the app rerun lane."""
    if bool(st.session_state.get("foreground_navigation_guard", False)):
        return True
    until = float(st.session_state.get("foreground_ui_settle_until", 0.0) or 0.0)
    if until <= 0.0:
        return False
    if time.time() < until:
        return True
    st.session_state.foreground_ui_settle_until = 0.0
    return False


def claim_foreground_interaction(
    action_group: str,
    *,
    debounce_seconds: float = UI_DEBOUNCE_DEFAULT_SECONDS,
    settle_seconds: float = UI_FOREGROUND_SETTLE_SECONDS,
) -> bool:
    """Claim one user-action lane and ignore duplicate rapid clicks.

    Streamlit already performs one rerun for a widget click. The white/stale
    workspace regressions came from letting a second queued click mutate the
    same pagination/navigation state while the first rerun was still settling,
    often combined with an explicit ``st.rerun()``. This helper does not rerun
    anything; it only rejects a duplicate action from the same interaction
    group for a very short window and arms the existing background-maintenance
    guard for the accepted click.
    """
    key = str(action_group or "foreground").strip() or "foreground"
    if not workspace_interaction_allowed():
        trace_action(key, outcome="ignored-session-transition")
        return False
    now = time.monotonic()
    try:
        debounce = max(0.0, float(debounce_seconds))
    except (TypeError, ValueError):
        debounce = UI_DEBOUNCE_DEFAULT_SECONDS

    stamps = dict(st.session_state.get("foreground_action_stamps") or {})
    # One short global lane protects *different* expensive controls too. Without
    # this, a rapid Next -> tab -> filter sequence could bypass the per-action
    # debounce because every click used a different action_group.
    global_key = "__mailmind_global_foreground__"
    global_last = float(stamps.get(global_key, 0.0) or 0.0)
    global_debounce = min(max(debounce, 0.0), UI_GLOBAL_DEBOUNCE_CAP_SECONDS)
    if global_debounce and now - global_last < global_debounce:
        arm_foreground_interaction(settle_seconds=settle_seconds)
        trace_action(key, outcome="rejected-global-debounce", debounce_ms=int(global_debounce * 1000))
        return False

    last = float(stamps.get(key, 0.0) or 0.0)
    if debounce and now - last < debounce:
        arm_foreground_interaction(settle_seconds=settle_seconds)
        trace_action(key, outcome="rejected-action-debounce", debounce_ms=int(debounce * 1000))
        return False

    stamps[global_key] = now
    stamps[key] = now
    # Keep this tiny map bounded during long desktop sessions.
    if len(stamps) > 32:
        cutoff = now - 10.0
        stamps = {name: ts for name, ts in stamps.items() if float(ts or 0.0) >= cutoff}
        stamps[key] = now
    st.session_state.foreground_action_stamps = stamps
    arm_foreground_interaction(settle_seconds=settle_seconds)
    trace_action(key, outcome="accepted", settle_ms=int(max(0.0, float(settle_seconds)) * 1000))
    return True

