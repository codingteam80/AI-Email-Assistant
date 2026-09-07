# Sidebar UI: legacy IMAP login helper, logout button, and account status.
#
# Scope note: the current full-page login lives in ui/login.py. This legacy
# sidebar helper keeps the same provider-detection behavior for compatibility.
import html as html_lib
from threading import Lock, Thread
import time

import streamlit as st

from config import UI_FOREGROUND_SETTLE_SECONDS

from services.ui_interaction_service import arm_foreground_interaction, workspace_interaction_allowed
from services.network_status_service import provider_connection_status
from services.white_stale_trace_service import trace_action, trace_stage
from services.streamlit_latency_profiler_service import mark_generate_click

from config import AUTO_BATCH_WAIT_SECONDS, OLLAMA_MODEL

from ui.inbox_notifications import push_summary_toast
from ui.notification_center import close_notification_store
from ui.notification_center import record_notification

from email_handler.provider_detect import detect_provider
from services.auth_service import login, logout
from storage.session_store import create_session, delete_session
from ui.markup import section_label


def render_login_form():
    # Render the universal IMAP login form.
    st.markdown(section_label("Email Login"), unsafe_allow_html=True)

    email_address = st.text_input(
        "Email address", key="login_email", placeholder="you@example.com"
    )

    detection = None
    if email_address and "@" in email_address:
        cache_key = f"detect::{email_address.lower()}"
        if cache_key not in st.session_state:
            with st.spinner("Checking your email provider..."):
                st.session_state[cache_key] = detect_provider(email_address)
        detection = st.session_state[cache_key]

    provider_not_found = bool(
        detection and not detection.get("supported")
    )
    if provider_not_found:
        st.error("Couldn't find this account")

    password = st.text_input(
        "Password", type="password", key="login_password",
        placeholder="App password or account password",
    )

    st.caption(
        "Outlook/Hotmail accounts must use Continue with Microsoft on the "
        "main login page. Gmail, Yahoo, and some other providers may require "
        "an app password when 2-factor authentication is enabled."
    )

    login_clicked = st.button("Login", key="login_button", type="primary", use_container_width=True)

    if login_clicked:
        with st.spinner("Connecting..."):
            if detection and detection["supported"]:
                result = login(email_address, password)
            elif provider_not_found:
                result = {
                    "success": False,
                    "error": "Couldn't find this account",
                }
            else:
                result = {
                    "success": False,
                    "error": "Enter a valid email address to continue.",
                }

        if result["success"]:
            token = create_session(result["client"], email_address)
            st.session_state.imap_client = result["client"]
            st.session_state.logged_in = True
            st.session_state.email_address = email_address
            st.session_state.session_token = token
            st.query_params["s"] = token
            st.rerun()
        else:
            st.error(result["error"])


# Request logout from transient UI (the account popover). The callback only
# arms a popover-free handoff frame; provider/store teardown is deliberately
# deferred until the browser has had one clean render cycle without the portal.
def request_logout() -> None:
    # Ignore duplicate/stale clicks from the account popover. Diagnostic wrappers
    # can report nested callback-start breadcrumbs, but only one accepted action
    # may own the logout transition.
    if not bool(st.session_state.get("logged_in", False)):
        trace_action("account-logout-request", outcome="ignored-already-signed-out")
        return
    if (
        bool(st.session_state.get("logout_handoff_requested", False))
        or bool(st.session_state.get("logout_requested", False))
        or bool(st.session_state.get("logout_in_progress", False))
    ):
        trace_action("account-logout-request", outcome="ignored-duplicate")
        return

    trace_action("account-logout-request", outcome="accepted")
    # Block every stale workspace callback immediately, but do NOT tear down the
    # provider/database from the popover callback's next root run. app.py first
    # mounts a dedicated Signing out frame, then promotes to root-owned teardown.
    st.session_state.logout_in_progress = True
    st.session_state.logout_handoff_requested = True
    st.session_state.logout_handoff_started_at = time.monotonic()
    st.session_state.foreground_navigation_guard = True

    # Close root-owned notification overlay state before the handoff. Do not
    # touch notification_center_filter here because it is a mounted widget key;
    # mutating only these non-widget flags avoids a stale widget-state race.
    st.session_state.notification_center_open = False
    st.session_state.notification_center_expanded = False
    st.session_state.notification_center_root_reconcile = False
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)


def _disconnect_provider_after_workers(client, futures) -> bool:
    # Provider disconnect can block on a stale socket/network close for many
    # seconds. Never hold the Streamlit root teardown on that I/O: keep the
    # client alive in a detached daemon cleanup and, if a worker still owns it,
    # wait for those futures by callback before disconnecting. The signed-out
    # session can therefore render immediately without cutting a live provider
    # call out from under an in-flight worker.
    if client is None:
        return False

    active = [future for future in futures if future is not None and not future.done()]

    def _disconnect() -> None:
        try:
            logout(client)
        except Exception:
            pass

    def _start_disconnect_thread() -> None:
        Thread(
            target=_disconnect,
            name="mailmind-provider-logout",
            daemon=True,
        ).start()

    if not active:
        _start_disconnect_thread()
        return True

    state = {"remaining": len(active), "started": False}
    lock = Lock()

    def _disconnect_when_done(_future) -> None:
        should_start = False
        with lock:
            state["remaining"] -= 1
            if state["remaining"] <= 0 and not state["started"]:
                state["started"] = True
                should_start = True
        if should_start:
            _start_disconnect_thread()

    for future in active:
        future.add_done_callback(_disconnect_when_done)
    return True


def _close_store_after_workers(store, futures) -> None:
    # Background workers keep direct references to EmailStore. Never close that
    # SQLite connection out from under an in-flight worker. If anything is still
    # running, close the retired store as soon as the last worker finishes.
    if store is None:
        return
    active = [future for future in futures if future is not None and not future.done()]
    if not active:
        try:
            store.close()
        except Exception:
            pass
        return

    state = {"remaining": len(active), "closed": False}
    lock = Lock()

    def _close_when_done(_future) -> None:
        with lock:
            state["remaining"] -= 1
            if state["remaining"] > 0 or state["closed"]:
                return
            state["closed"] = True
        try:
            store.close()
        except Exception:
            pass

    for future in active:
        future.add_done_callback(_close_when_done)


# Clear the signed-in account and return to the login page. This function is
# called only from the stable app root after ``request_logout`` has rerun out of
# the account popover.
def perform_pending_logout(*, rerun: bool = True) -> None:
    teardown_started = time.monotonic()
    trace_stage("logout-teardown-start")

    worker_futures = [
        st.session_state.get("security_catchup_future"),
        st.session_state.get("new_mail_security_refinement_future"),
        st.session_state.get("mailbox_sync_future"),
        st.session_state.get("summary_future"),
        st.session_state.get("draft_future"),
    ]

    # Do not wait for Ollama/provider workers here. ``shutdown(wait=True)`` can
    # hold the Streamlit script with no mounted workspace and produce a full
    # white frame. Cancel queued work and let any already-running call unwind.
    executors_started = time.monotonic()
    executor_count = 0
    for executor_key in (
        "security_catchup_executor",
        "new_mail_security_refinement_executor",
        "mailbox_sync_executor",
        "summary_executor",
        "draft_executor",
    ):
        executor = st.session_state.get(executor_key)
        if executor is not None:
            executor_count += 1
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
    trace_stage(
        "logout-executors-detached",
        elapsed_ms=int((time.monotonic() - executors_started) * 1000),
        executor_count=executor_count,
        active_worker_count=sum(
            1 for future in worker_futures if future is not None and not future.done()
        ),
    )

    provider_started = time.monotonic()
    provider_disconnect_scheduled = _disconnect_provider_after_workers(
        st.session_state.get("imap_client"),
        worker_futures,
    )
    trace_stage(
        "logout-provider-disconnect-scheduled",
        elapsed_ms=int((time.monotonic() - provider_started) * 1000),
        scheduled=bool(provider_disconnect_scheduled),
        active_worker_count=sum(
            1 for future in worker_futures if future is not None and not future.done()
        ),
    )

    session_started = time.monotonic()
    delete_session(st.session_state.get("session_token"))
    trace_stage(
        "logout-session-deleted",
        elapsed_ms=int((time.monotonic() - session_started) * 1000),
    )

    stores_started = time.monotonic()
    email_store = st.session_state.get("email_store")
    _close_store_after_workers(email_store, worker_futures)

    notification_store = st.session_state.get("notification_store")
    if notification_store is not None:
        close_notification_store()
    summary_store = st.session_state.get("summary_store")
    if summary_store is not None:
        try:
            summary_store.close()
        except Exception:
            pass
    trace_stage(
        "logout-stores-retired",
        elapsed_ms=int((time.monotonic() - stores_started) * 1000),
    )

    state_clear_started = time.monotonic()
    st.query_params.clear()
    for key in [
        "imap_client", "logged_in", "email_address", "session_token",
        "email_store", "summary_store", "notification_store", "active_store_account",
        "selected_uid", "emails", "inbox_loaded", "email_bodies",
        "inbox_offset", "inbox_total", "inbox_has_more", "loading",
        "last_mail_check", "new_mail_count", "checked_uids",
        "summary_mode", "batch_summary_enabled", "summary_mode_choice",
        "auto_summary_enabled", "auto_summary_type_choice",
        "auto_summary_batch_started_at", "auto_summary_batch_deadline",
        "pending_auto_summary_uids",
        "auto_summary_queue_updated_at", "auto_summary_not_before",
        "auto_summary_start_requested", "auto_summary_retry_after",
        "auto_summary_monitor_seen_generation",
        "pending_security_hydration_uids",
        "pending_new_mail_notification_uids",
        "new_mail_security_refinement_future",
        "new_mail_security_refinement_executor",
        "new_mail_security_refinement_uids",
        "new_mail_security_monitor_seen_generation",
        "security_catchup_future", "security_catchup_executor",
        "security_catchup_progress", "security_catchup_batch_size",
        "security_catchup_session_total", "security_catchup_remaining",
        "security_catchup_unsafe_count", "security_catchup_completed_at",
        "security_catchup_next_at", "security_catchup_monitor_seen_generation",
        "mailbox_monitor_seen_generation", "app_run_generation",
        "mailbox_sync_in_progress", "mailbox_sync_future", "mailbox_sync_executor",
        "mailbox_sync_account", "pending_mailbox_remote_count",
        "pending_mailbox_detected_at", "pending_mailbox_location_change",
        "summary_job_origin",
        "search_active", "search_results", "search_total",
        "inbox_search_offset", "inbox_search_page_size",
        "full_synced", "full_sync_attempted", "initial_sync_error",
        "initial_security_analysis_incomplete",
        "provider_connection_state", "provider_connection_error",
        "provider_connection_notice_active", "inbox_search_query",
        "inbox_search_submit", "inbox_search_clear",
        "summaries", "selected_summary_uid", "summary_processing", "open_summary_tab",
        "summary_future", "summary_job_uids", "summary_executor",
        "summary_progress",
        "draft_future", "draft_executor", "draft_processing",
        "active_workspace", "summary_filter", "summary_search_query",
        "summary_task_filter", "summary_unread_only",
        "summary_type_filter", "summary_status_filter", "summary_priority_filter",
        "summary_arrange_by", "summary_sort_order",
        "summary_filter_popover_version", "summary_offset",
        "summary_page_size",
        "todo_search_query", "todo_status_filter",
        "todo_priority_filter", "todo_deadline_filter",
        "todo_action_needed_only",
        "todo_sort_by", "todo_filter_popover_version", "todo_notice",
        "todo_offset", "todo_page_size",
        "switch_to_summary",
        "clear_checked_after_summary", "new_email_uids",
        "clear_checked_after_refresh",
        "inbox_filter", "inbox_arrange_by", "inbox_sort_order",
        "spam_category_filter", "spam_detected_only",
        "spam_reviewed_pinned_uid",
        "inbox_loaded_view_signature",
        "login_authenticating", "login_error", "login_email_error",
        "post_login_loading",
        "login_submit_requested", "login_manual_mode",
        "suppress_login_autofill",
        "login_email", "login_password", "login_server", "login_port",
        "pending_login_email", "pending_login_password",
        "pending_login_server", "pending_login_port",
        "microsoft_login_active", "microsoft_login_error",
        "microsoft_login_redirect_url",
        "profile_image_url",
        "profile_display_name",
        "summary_settings_dialog_open",
        "_mmdbg_widget_fingerprints",
        "logout_handoff_requested", "logout_handoff_started_at",
        "logout_requested", "logout_in_progress", "foreground_navigation_guard", "root_render_in_progress",
    ]:
        st.session_state.pop(key, None)

    for key in list(st.session_state.keys()):
        if (
            key.startswith("detect::")
            or key.startswith("todo_")
            or key.startswith("sidebar_account_")
        ):
            st.session_state.pop(key, None)

    st.session_state.suppress_login_autofill = True
    st.session_state.login_manual_mode = False
    st.session_state.login_email_error = ""
    trace_stage(
        "logout-state-cleared",
        elapsed_ms=int((time.monotonic() - state_clear_started) * 1000),
        total_elapsed_ms=int((time.monotonic() - teardown_started) * 1000),
    )

    # The main app uses an explicit clean signed-out rerun after this helper.
    # Retain the legacy rerun option only for older callers that still invoke
    # this helper directly.
    if rerun:
        st.rerun()


# Legacy direct logout renderer retained for compatibility with older callers.
def render_logout_button():
    st.button(
        "↪ Logout",
        key="logout_button",
        use_container_width=True,
        type="tertiary",
        on_click=request_logout,
    )


# Resolve a provider display name without issuing an extra network request.
def _account_display_name() -> str:
    configured = str(st.session_state.get("profile_display_name") or "").strip()
    if configured:
        return configured

    client = st.session_state.get("imap_client")
    profile = getattr(client, "_profile", None)
    if isinstance(profile, dict):
        display_name = str(profile.get("displayName") or "").strip()
        if display_name:
            return display_name
    return ""


# Build one provider-neutral identity for the sidebar account card.
def _account_card_identity() -> tuple[str, str, str]:
    email_address = str(st.session_state.get("email_address", "") or "").strip()
    display_name = _account_display_name()

    # Some providers do not expose a profile display name. Keep the UI shape
    # identical by falling back to the mailbox local-part rather than changing
    # the account-card markup per provider.
    if not display_name and email_address:
        display_name = email_address.split("@", 1)[0].strip()
    if not display_name:
        display_name = "Signed-in account"

    avatar_initial = next(
        (character.upper() for character in display_name if character.isalnum()),
        "A",
    )
    return display_name, email_address, avatar_initial


# Show one universal clickable account card for every supported provider.
def render_status():
    display_name, email_address, avatar_initial = _account_card_identity()
    connection_label, connection_issue = provider_connection_status()
    connection_class = " is-issue" if connection_issue else ""

    email_markup = (
        f'<div class="sidebar-account-menu-email" title="{html_lib.escape(email_address, quote=True)}">'
        f'{html_lib.escape(email_address)}</div>'
        if email_address
        else ""
    )

    with st.container(border=False, key="sidebar_account_menu"):
        account_card_markup = (
            '<div class="sidebar-account-menu-card" aria-hidden="true">'
            f'<div class="sidebar-account-menu-avatar" aria-hidden="true">{html_lib.escape(avatar_initial)}</div>'
            '<div class="sidebar-account-menu-copy">'
            f'<div class="sidebar-account-menu-name">{html_lib.escape(display_name)}</div>'
            f'{email_markup}'
            f'<div class="sidebar-account-menu-status{connection_class}">{html_lib.escape(connection_label)} <span></span></div>'
            '</div>'
            '<div class="sidebar-account-menu-chevron">›</div>'
            '</div>'
        )
        st.html(account_card_markup)

        with st.popover(
            "Account menu",
            width="stretch",
            key="sidebar_account_popover",
        ):
            st.markdown(
                '<div class="sidebar-account-popover-marker" aria-hidden="true"></div>',
                unsafe_allow_html=True,
            )
            # Do not mount st.dialog from inside the account popover. Publish
            # the launch intent in the widget callback; the click's natural root
            # rerun lets app.py mount the dialog without a second forced rerun.
            st.button(
                "Settings",
                key="sidebar_account_settings",
                icon=":material/settings:",
                type="tertiary",
                use_container_width=True,
                on_click=_request_summary_settings_dialog,
            )

            st.markdown(
                '<div class="sidebar-account-popover-divider" aria-hidden="true"></div>',
                unsafe_allow_html=True,
            )

            st.button(
                "Logout",
                key="sidebar_account_logout",
                icon=":material/logout:",
                type="tertiary",
                use_container_width=True,
                on_click=request_logout,
            )


def render_logout_handoff_anchor() -> None:
    """Keep only the native account-popover anchor during logout handoff.

    The original Settings/Logout buttons are intentionally not remounted here.
    A just-clicked Streamlit button can remain truthy for the next render;
    remounting it inside the handoff frame lets the stale portal briefly replay
    at the viewport edge before teardown. The popover key/marker stay mounted so
    BaseWeb can retire the existing portal against a stable anchor.
    """
    with st.container(border=False, key="sidebar_account_menu"):
        # The sidebar is already fully hidden by the logout-handoff marker CSS,
        # so the visual account-card markup is unnecessary in this transient
        # frame. Keep the same keyed popover anchor only.
        with st.popover(
            "Account menu",
            width="stretch",
            key="sidebar_account_popover",
        ):
            st.markdown(
                '<div class="sidebar-account-popover-marker" aria-hidden="true"></div>',
                unsafe_allow_html=True,
            )


def _request_summary_settings_dialog() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="sidebar", callback="_request_summary_settings_dialog")
        return
    trace_action("summary-settings-open")
    st.session_state.summary_settings_dialog_open = True
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)


def _normalize_summary_settings_state() -> None:
    # Keep one summary type for both manual and automatic flows.
    mode = str(st.session_state.get("summary_mode") or "manual").lower()
    auto_type = str(st.session_state.get("auto_summary_type_choice") or "Individual")

    if mode == "batch" or auto_type == "Batch":
        summary_type = "Batch"
    else:
        summary_type = "Individual"

    st.session_state.summary_mode = "batch" if summary_type == "Batch" else "manual"
    st.session_state.batch_summary_enabled = summary_type == "Batch"
    st.session_state.summary_mode_choice = (
        "Batch Summary" if summary_type == "Batch" else "Individual Summary"
    )
    st.session_state.auto_summary_type_choice = summary_type

    # Mirror persisted values into the two Settings widgets before render.
    st.session_state.cfg_auto_summary_checkbox = bool(
        st.session_state.get("auto_summary_enabled", False)
    )
    st.session_state.cfg_summary_type_radio = summary_type

    # Drop obsolete widget state from older Settings UI versions.
    for legacy_key in (
        "cfg_summary_mode_choice",
        "cfg_auto_enabled",
        "cfg_auto_type_choice",
        "cfg_mode_manual",
        "cfg_mode_batch",
        "cfg_auto_switch",
        "cfg_type_individual",
        "cfg_type_batch",
        "auto_summary_apply_to",
        "auto_summary_batch_wait_seconds",
        "cfg_apply_to_choice",
        "cfg_batch_wait_choice",
        "cfg_single_email_fallback",
    ):
        st.session_state.pop(legacy_key, None)


def _persist_summary_preferences() -> None:
    # Persist only explicit Settings choices. Runtime queues/futures remain
    # session-local and are intentionally never written to account preferences.
    store = st.session_state.get("email_store")
    if store is None or not hasattr(store, "set_user_preferences"):
        return
    generation_mode = (
        "Automatic"
        if bool(st.session_state.get("auto_summary_enabled", False))
        else "Manual"
    )
    summary_type = str(
        st.session_state.get("auto_summary_type_choice") or "Individual"
    )
    summary_type = "Batch" if summary_type == "Batch" else "Individual"
    store.set_user_preferences(
        {
            "summary_generation_mode": generation_mode,
            "summary_type": summary_type,
        }
    )


def _set_auto_summary_enabled(enabled: bool) -> None:
    # Apply Auto Summary state and always start from a fresh future-mail queue.
    enabled = bool(enabled)
    if bool(st.session_state.get("auto_summary_enabled", False)) == enabled:
        return

    st.session_state.auto_summary_enabled = enabled
    st.session_state.pending_auto_summary_uids = set()
    st.session_state.auto_summary_queue_updated_at = 0.0
    st.session_state.auto_summary_not_before = 0.0
    st.session_state.auto_summary_batch_started_at = 0.0
    st.session_state.auto_summary_batch_deadline = 0.0
    st.session_state.auto_summary_start_requested = False
    st.session_state.auto_summary_retry_after = 0.0


def _on_cfg_auto_summary_change() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="sidebar", callback="_on_cfg_auto_summary_change")
        return
    trace_action("summary-settings-auto-toggle", enabled=bool(st.session_state.get("cfg_auto_summary_checkbox", False)))
    _set_auto_summary_enabled(
        bool(st.session_state.get("cfg_auto_summary_checkbox", False))
    )
    _persist_summary_preferences()


def _apply_summary_type(summary_type: str) -> None:
    # The selected type is the default for both manual and automatic summaries.
    summary_type = "Batch" if summary_type == "Batch" else "Individual"
    mode = "batch" if summary_type == "Batch" else "manual"

    st.session_state.summary_mode = mode
    st.session_state.batch_summary_enabled = mode == "batch"
    st.session_state.summary_mode_choice = (
        "Batch Summary" if mode == "batch" else "Individual Summary"
    )
    st.session_state.auto_summary_type_choice = summary_type

    # Preserve current queue timing behavior if the type changes while Auto
    # Summary already has future messages waiting.
    if st.session_state.get("pending_auto_summary_uids"):
        import time

        now = time.time()
        if summary_type == "Batch":
            st.session_state.auto_summary_batch_started_at = now
            st.session_state.auto_summary_batch_deadline = now + AUTO_BATCH_WAIT_SECONDS
            st.session_state.auto_summary_not_before = now + AUTO_BATCH_WAIT_SECONDS
        else:
            st.session_state.auto_summary_batch_started_at = 0.0
            st.session_state.auto_summary_batch_deadline = 0.0
            st.session_state.auto_summary_not_before = now + 3.0
        st.session_state.auto_summary_start_requested = False


def _on_cfg_summary_type_change() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="sidebar", callback="_on_cfg_summary_type_change")
        return
    trace_action("summary-settings-type-change", value=str(st.session_state.get("cfg_summary_type_radio") or "Individual"))
    _apply_summary_type(
        str(st.session_state.get("cfg_summary_type_radio") or "Individual")
    )
    _persist_summary_preferences()


def _render_summary_settings_dialog_body() -> None:
    # Summary Settings is intentionally a persistent dialog: all controls save
    # immediately, and the dialog closes only through the explicit X control.
    _normalize_summary_settings_state()

    with st.container(key="summary_settings_body", gap=0):
        if st.button(
            "×",
            key="summary_settings_close",
            type="tertiary",
            help="Close Summary Settings",
        ):
            trace_action("summary-settings-close")
            st.session_state.summary_settings_dialog_open = False
            arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
            st.rerun()

        st.markdown(
            """
            <span class="summary-settings-shell" aria-hidden="true"></span>
            <div class="summary-settings-header">
                <span class="summary-settings-gear" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none">
                        <path d="M9.6 2.8h4.8l.6 2.2c.5.2 1 .5 1.4.8l2.2-.7 2.4 4.1-1.7 1.6c0 .3.1.7.1 1s0 .7-.1 1l1.7 1.6-2.4 4.1-2.2-.7c-.4.3-.9.6-1.4.8l-.6 2.2H9.6L9 18.6c-.5-.2-1-.5-1.4-.8l-2.2.7L3 14.4l1.7-1.6a6.8 6.8 0 0 1 0-2L3 9.2l2.4-4.1 2.2.7c.4-.3.9-.6 1.4-.8l.6-2.2Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
                        <circle cx="12" cy="11.8" r="2.8" stroke="currentColor" stroke-width="1.7"/>
                    </svg>
                </span>
                <div class="summary-settings-title">Summary Settings</div>
            </div>
            <div class="summary-settings-subtitle">Choose how summaries are handled by default.</div>
            """,
            unsafe_allow_html=True,
        )

        auto_summary_processing = bool(
            st.session_state.get("summary_processing")
            and str(st.session_state.get("summary_job_origin") or "manual") == "auto"
        )
        if auto_summary_processing:
            st.markdown(
                '<div class="summary-settings-processing-note">'
                '<span class="summary-settings-processing-note-icon" aria-hidden="true">i</span>'
                '<span>Automatic summary settings are temporarily unavailable while summarization is in progress.</span>'
                '</div>',
                unsafe_allow_html=True,
            )

        with st.container(key="summary_settings_auto_section", gap=0):
            st.toggle(
                "Automatic Summary",
                key="cfg_auto_summary_checkbox",
                on_change=_on_cfg_auto_summary_change,
                disabled=auto_summary_processing,
            )
            st.markdown(
                '<div class="summary-settings-auto-copy">'
                '<div class="summary-settings-auto-description">Automatically summarize new emails</div>'
                '<div class="summary-settings-helper summary-settings-auto-helper">'
                'When disabled, summaries are generated manually.'
                '</div></div>',
                unsafe_allow_html=True,
            )

        with st.container(key="summary_settings_type_section", gap=0):
            st.markdown(
                '<div class="summary-settings-section-title">Default Summary Type</div>'
                '<div class="summary-settings-helper summary-settings-type-intro">'
                'This will be used as the default summary type.'
                '</div>',
                unsafe_allow_html=True,
            )
            st.radio(
                "Summary Type",
                options=("Individual", "Batch"),
                key="cfg_summary_type_radio",
                label_visibility="collapsed",
                on_change=_on_cfg_summary_type_change,
                disabled=auto_summary_processing,
            )

        auto_enabled = bool(st.session_state.get("auto_summary_enabled", False))
        summary_type = str(
            st.session_state.get("auto_summary_type_choice") or "Individual"
        )
        mode_label = "Automatic" if auto_enabled else "Manual"
        with st.container(key="summary_settings_mode_section", gap=0):
            st.markdown(
                f"""
                <div class="summary-settings-current-mode">
                    <span class="summary-settings-info-icon">i</span>
                    <span><strong>Current default:</strong> <span class="summary-settings-current-value">{html_lib.escape(mode_label)}</span><span class="summary-settings-current-separator">•</span><span class="summary-settings-current-value">{html_lib.escape(summary_type)}</span></span>
                </div>
                """,
                unsafe_allow_html=True,
            )


@st.dialog(
    " ",
    width="large",
    dismissible=False,
)
def _show_summary_settings_dialog() -> None:
    # Keep Streamlit's native dialog portal. Only the inner card is styled.
    # This function is intentionally called from the app root, never from the
    # account popover, so fragment/background reruns cannot orphan the portal.
    _render_summary_settings_dialog_body()


def render_summary_settings_dialog() -> None:
    # Root-owned launcher for the persistent Settings dialog. The account menu
    # only flips this state; app.py calls this on normal full-app reruns.
    if bool(st.session_state.get("summary_settings_dialog_open", False)):
        _show_summary_settings_dialog()


def _queue_manual_summary_generation() -> None:
    """Persist one Generate Summary click before the app body reruns.

    Streamlit executes widget callbacks before the normal script body.  Capturing
    the exact UID set here makes a large multi-selection a durable one-shot
    request even if a timed/background fragment interrupts the following root
    render.  The normal app/controller path still owns validation, duplicate
    handling, Security gates, worker launch, and persistence.
    """
    if not workspace_interaction_allowed():
        trace_action("manual-summary-generate-queued", outcome="ignored-session-transition")
        return
    if bool(st.session_state.get("summary_processing", False)):
        trace_action("manual-summary-generate-queued", outcome="ignored-processing")
        return

    selected_uids = {
        str(uid).strip()
        for uid in st.session_state.get("checked_uids", set())
        if str(uid).strip()
    }
    mode = str(st.session_state.get("summary_mode") or "manual")

    # Preserve the existing Batch minimum/warning behavior.  Invalid Batch
    # clicks are handled by render_summary_button below and are never queued.
    if mode == "batch" and len(selected_uids) < 2:
        return
    if not selected_uids:
        return

    # Collapse rapid duplicate button events into the same pending request.
    if bool(st.session_state.get("manual_summary_generate_requested", False)):
        arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
        return

    st.session_state.manual_summary_generate_requested = True
    st.session_state.manual_summary_generate_uids = tuple(sorted(selected_uids))
    st.session_state.manual_summary_generate_selected_count = len(selected_uids)
    st.session_state.manual_summary_generate_mode = mode

    # Arm the stable baseline blocker inside the widget callback itself. Streamlit
    # runs callbacks before the next script body, so this state is what makes the
    # Generate click durable and prevents repeated callbacks while Security/duplicate
    # preflight is running. Keep that proven behavior, but use the same visible copy
    # and initial progress as the real Summary worker so the user sees one continuous
    # "Generating summary/summaries" modal instead of a separate Preparing stage.
    count = len(selected_uids)
    st.session_state.app_loading_active = True
    st.session_state.app_loading_title = (
        "Generating summary" if count == 1 else "Generating summaries"
    )
    st.session_state.app_loading_subtitle = (
        "Analyzing selected email..." if count == 1 else "Analyzing selected emails..."
    )
    st.session_state.app_loading_detail = f"0 of {count}"
    st.session_state.manual_summary_prepare_overlay_owned = True

    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
    mark_generate_click(selected_count=len(selected_uids), mode=mode)
    trace_action(
        "manual-summary-generate-queued",
        outcome="accepted",
        selected_count=len(selected_uids),
        mode=mode,
    )


def render_summary_button(disabled: bool = False) -> bool:
    # Render Inbox AI Tools and the isolated Settings launcher.
    st.markdown(section_label("AI Tools"), unsafe_allow_html=True)
    _normalize_summary_settings_state()

    selected_count = len(st.session_state.get("checked_uids", set()))
    batch_mode = st.session_state.get("summary_mode") == "batch"

    clicked = st.button(
        "✣  Generate Summary",
        key="generate_summary_button",
        type="tertiary",
        use_container_width=True,
        disabled=disabled,
        on_click=_queue_manual_summary_generation,
    )

    if clicked and batch_mode and selected_count < 2:
        push_summary_toast(
            "Select at least 2 emails to create a Batch Summary.",
            "warning",
            details=[f"Selected emails: {selected_count}"],
            event_type="batch-selection-warning",
        )
        return False

    return clicked


def render_ollama_prompt(ollama_status: dict):
    # Ambient Ollama/model availability is background state, so persist it in
    # the Bell without interrupting the user. Manual AI actions surface their own
    # immediate Toast/error feedback when they fail.
    #
    # A small state signature prevents the same warning from being replayed on
    # every Streamlit rerun. Returning to a ready state resets the signature so a
    # later outage can be reported once again.
    if not ollama_status.get("available"):
        signature = "ollama-unavailable"
        if st.session_state.get("ollama_notice_signature") != signature:
            st.session_state.ollama_notice_signature = signature
            record_notification(
                title="AI unavailable",
                message="Ollama is not running. Start or restart Ollama to use AI features.",
                kind="warning",
                workspace="summary",
                details=[],
                event_type="ollama-unavailable",
            )
        return

    if not ollama_status.get("model_ready"):
        signature = "ollama-model-missing"
        if st.session_state.get("ollama_notice_signature") != signature:
            st.session_state.ollama_notice_signature = signature
            model_name = str(OLLAMA_MODEL or "").strip() or "configured model"
            record_notification(
                title="AI model unavailable",
                message="The required local AI model is not ready. Start Ollama and make sure the model is installed.",
                kind="warning",
                workspace="summary",
                details=[],
                event_type="qwen-model-missing",
            )
        return

    st.session_state.ollama_notice_signature = "ollama-ready"


def render_inbox_filters(emails: list[dict]):
    # Render Inbox-only filters using compact aligned sidebar rows.
    unread_uids = st.session_state.get("new_email_uids", set())
    counts = {
        "all": st.session_state.get("inbox_total", len(emails)),
        "unread": sum(str(item.get("uid")) in unread_uids for item in emails),
    }
    st.divider()
    st.markdown(section_label("Filters"), unsafe_allow_html=True)
    active = st.session_state.get("inbox_filter", "all")

    for filter_key, icon, label in [
        ("all", "☷", "All Inboxes"),
        ("unread", "✉", "Unread"),
    ]:
        with st.container(key=f"sidebar_filter_row_{filter_key}"):
            clicked = st.button(
                f"{icon}  {label}",
                key=f"sidebar_inbox_filter_{filter_key}",
                type="primary" if active == filter_key else "secondary",
                use_container_width=True,
            )
            st.markdown(
                f'<span class="sidebar-filter-count">{counts[filter_key]:,}</span>',
                unsafe_allow_html=True,
            )
            if clicked:
                st.session_state.inbox_filter = filter_key
                arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
                st.rerun()

