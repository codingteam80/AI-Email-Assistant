import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from controllers.inbox_controller import (
    handle_inbox_actions,
    has_checked_emails,
    load_inbox_if_needed,
    monitor_mailbox_changes,
    monitor_new_mail_security_refinement,
    monitor_security_catchup,
    process_pending_new_mail_security,
    process_pending_mailbox_sync,
    run_full_sync_if_needed,
    preclassify_pending_spam_security,
    queue_security_catchup_background_toast,
)
from controllers.draft_controller import monitor_draft_generation, render_draft_cancel_control
from controllers.summary_controller import (
    monitor_auto_summary_queue,
    monitor_summary_generation,
    process_pending_auto_summary,
    resume_deferred_summary_generation,
    start_summary_generation,
    render_summary_cancel_control,
)
from services.ai_service import get_ollama_status
from services.dialog_handoff_service import promote_pending_draft_dialog
from services.ollama_runtime_service import start_ollama_preload
from services.ui_interaction_service import foreground_interaction_is_settling
from services.white_stale_trace_service import (
    begin_app_run,
    complete_app_run,
    install_streamlit_diagnostics,
    trace_action,
    trace_stage,
)
from services.streamlit_latency_profiler_service import (
    mark_generate_click,
    mark_summary_render_start,
    mark_summary_render_visible,
)
from controllers.session_controller import (
    apply_pending_refresh_resets,
    bind_store_to_signed_in_account,
    initialize_session_state,
    restore_saved_session,
    sync_mailmind_attention_refresh_state,
)
from ui.login import (
    render_loading_page,
    render_login_page,
    render_mailbox_connection_error_page,
)
from ui.loading import (
    clear_app_loading_state,
    render_active_app_loading_overlay,
)
from ui.notification_center import render_notification_center
from ui.inbox_notifications import (
    render_inbox_toasts,
    render_summary_confirmation,
    render_summary_toasts,
)
from ui.draft_window import render_draft_email_dialog, render_draft_email_window
from ui.sidebar import (
    render_ollama_prompt,
    render_status,
    render_logout_handoff_anchor,
    render_summary_button,
    render_summary_settings_dialog,
    perform_pending_logout,
)
from ui.markup import sidebar_brand
from ui.original_window import (
    render_original_email_dialog,
    render_original_email_window,
    render_spam_email_dialog,
)
from config import APP_WORKSPACE_HEIGHT, LOGOUT_HANDOFF_MIN_VISIBLE_SECONDS
from ui.styles import load_styles
from ui.scripts import load_scripts
from ui.tabs.inbox_tab import render_inbox_tab
from ui.tabs.navigation import INBOX_TAB, SPAM_TAB, SUMMARY_TAB, TODO_TAB, render_sidebar_navigation
from ui.tabs.summary_tab import render_summary_tab
from ui.tabs.todo_tab import (
    render_todo_tab,
    render_todo_toasts,
    publish_task_deadline_alerts,
    render_task_actions_dialog,
)

st.set_page_config(
    page_title="MailMind AI",
    page_icon=os.path.join(os.path.dirname(__file__), "ui", "assets", "mailmind_favicon.png"),
    layout="wide",
    initial_sidebar_state="expanded",
)
load_styles()
load_scripts()

initialize_session_state()
install_streamlit_diagnostics()

# This counter advances only on a full-app rerun. Timed fragments keep the
# same generation, which lets background monitors distinguish their own timer
# reruns from ordinary user clicks that rerun the whole Streamlit app.
st.session_state.app_run_generation = int(
    st.session_state.get("app_run_generation", 0) or 0
) + 1
begin_app_run()
trace_stage("session-initialized", logged_in=bool(st.session_state.get("logged_in")))

# One provider-neutral security mailbox view: Inbox plus Spam/Junk only.
FOLDER = "ALL_MAIL"

# Restore a live server-side login after a browser refresh.
restore_saved_session()
# On F5 a new Streamlit Session State starts empty. Arm the attention-state
# restore before account stores are rebound so Inbox Unread is never consumed
# merely by refreshing the browser.
sync_mailmind_attention_refresh_state()
trace_stage("session-restored", logged_in=bool(st.session_state.get("logged_in")))

# Keep every post-login Syncing/Analyzing surface inside one root-owned
# replaceable slot.  A completed backend run can otherwise leave the browser
# displaying the previous fixed loading HTML until F5, even though the Inbox
# has already rendered.  Reusing and explicitly clearing this slot gives the
# frontend one deterministic subtree to replace across login/sync/security
# transitions; it adds no timer, callback, sleep, or extra rerun.
post_login_transition_slot = st.empty()

# Logout starts inside Streamlit's native account popover. A widget callback runs
# before the next full app script, so tearing the session down immediately can
# race the browser while that portal is still mounted. Use a short deterministic
# two-phase handoff: first render a dedicated Signing out overlay, keep that frame
# alive briefly so the browser can retire the popover portal, then explicitly
# rerun into root-owned teardown. Do not use st.stop() here: a stopped root run
# prevents a run_every fragment from getting the timer tick that promotes logout,
# which can strand the browser on a stale/blank frame.
if st.session_state.get("logout_handoff_requested"):
    # Measure the settling window from THIS handoff render, not from the
    # original popover callback. A delayed/duplicate browser event can postpone
    # the root rerun beyond 250 ms; using callback age would then skip the clean
    # handoff frame entirely and let the account portal flash at the page edge.
    logout_handoff_frame_started_at = time.monotonic()
    trace_stage("logout-handoff-render-start")
    # The account menu is a BaseWeb portal that can briefly survive after its
    # sidebar anchor is removed. Publish a marker before the handoff surface so
    # canonical CSS can hide only that stale account-menu portal while logout
    # is in progress. No JavaScript teardown or extra rerun is needed.
    st.html('<span class="logout-handoff-ui-marker" aria-hidden="true"></span>')

    # Preserve the native account-popover anchor for this one handoff frame.
    # Removing the sidebar anchor and the BaseWeb portal in the same React diff
    # can make the still-open Settings/Logout popover briefly re-anchor at the
    # viewport top. Keep the same keyed sidebar/footer/popover mounted but make
    # it visually inert via the logout marker CSS below. The next teardown run
    # removes it only after the handoff frame has settled.
    with st.sidebar:
        with st.container(key="sidebar_shell"):
            with st.container(key="sidebar_body"):
                st.empty()
            with st.container(key="sidebar_footer"):
                render_logout_handoff_anchor()

    render_loading_page(
        title="Signing you out",
        subtitle="Closing your current session safely.",
    )
    trace_stage("logout-handoff-render-complete")

    elapsed = time.monotonic() - logout_handoff_frame_started_at
    remaining = max(0.0, LOGOUT_HANDOFF_MIN_VISIBLE_SECONDS - elapsed)
    if remaining:
        trace_stage("logout-handoff-visible-wait", wait_ms=int(remaining * 1000))
        time.sleep(remaining)

    trace_stage("logout-handoff-promote")
    st.session_state.logout_handoff_requested = False
    st.session_state.logout_requested = True
    st.rerun()


# Actual provider/store teardown runs only after the popover-free handoff frame
# has been mounted. Teardown owns this run, then an explicit fresh signed-out
# rerun renders the login page.
if st.session_state.get("logout_requested"):
    trace_stage("logout-transition-root-start")
    perform_pending_logout(rerun=False)
    trace_stage(
        "logout-transition-teardown-complete",
        logged_in=bool(st.session_state.get("logged_in")),
    )
    st.rerun()


def _background_monitor_pause_requested() -> bool:
    # Root-owned dialogs and confirmations must not compete with timer/full-app
    # reruns. Background monitors resume automatically on the first stable run
    # after the overlay closes. Keep this list limited to durable root-level state
    # so ordinary popovers and workspace controls are unaffected.
    email_dialog_open = any(
        str(st.session_state.get(key) or "").strip()
        for key in ("draft_dialog_uid", "original_dialog_uid", "spam_email_dialog_uid")
    )
    return bool(
        email_dialog_open
        or str(st.session_state.get("todo_dialog_uid") or "").strip()
        or st.session_state.get("summary_settings_dialog_open")
        or st.session_state.get("summary_pending_confirmation")
        or st.session_state.get("summary_pending_delete")
    )


def render_active_email_dialog() -> None:
    # Render one summary action dialog from the app root.
    #
    # Keeping dialogs outside the Summary reader prevents fragment/background
    # reruns from temporarily unmounting their content and leaving a blank white
    # modal surface.
    draft_uid = str(st.session_state.get("draft_dialog_uid") or "").strip()
    original_uid = str(st.session_state.get("original_dialog_uid") or "").strip()
    spam_email_uid = str(st.session_state.get("spam_email_dialog_uid") or "").strip()
    if draft_uid:
        render_draft_email_dialog(draft_uid, folder=FOLDER)
    elif original_uid:
        render_original_email_dialog(original_uid, folder=FOLDER)
    elif spam_email_uid:
        render_spam_email_dialog(spam_email_uid, folder=FOLDER)


def render_app_sidebar():
    # Render navigation and AI Tools as permanent sidebar content.
    #
    # Generate Summary remains Inbox-scoped, but the control itself stays
    # mounted on every workspace so tab changes and reruns never make AI Tools
    # or Settings disappear.
    generate_clicked = False

    with st.sidebar:
        with st.container(key="sidebar_shell"):
            with st.container(key="sidebar_header"):
                st.markdown(
                    sidebar_brand("MailMind AI", "AI-Assisted Inbox &amp; Task Management"),
                    unsafe_allow_html=True,
                )
            with st.container(key="sidebar_body"):
                if st.session_state.logged_in:
                    render_sidebar_navigation()

                    ollama_status = get_ollama_status()
                    active_workspace = st.session_state.get("active_workspace", INBOX_TAB)
                    if active_workspace == INBOX_TAB:
                        render_ollama_prompt(ollama_status)
                    batch_mode = st.session_state.get("summary_mode") == "batch"
                    generate_clicked = render_summary_button(
                        disabled=(
                            active_workspace != INBOX_TAB
                            or ((not has_checked_emails() and not batch_mode))
                            or bool(st.session_state.get("summary_processing", False))
                            or not ollama_status["model_ready"]
                        )
                    )
                else:
                    st.markdown(
                        '<div class="sidebar-signed-out-note">Sign in to open your inbox and tools.</div>',
                        unsafe_allow_html=True,
                    )
            if st.session_state.logged_in:
                with st.container(key="sidebar_footer"):
                    render_status()

    return generate_clicked


if not st.session_state.logged_in:
    # A prior Syncing/Analyzing frame may still exist in the browser while an
    # OAuth callback or session transition is being reconciled. Clear the
    # root-owned transition slot before painting the signed-out/login surface.
    post_login_transition_slot.empty()
    # Keep the same logout portal-quarantine marker mounted on the signed-out
    # page as on the handoff frame.  BaseWeb/Streamlit portals can survive one
    # browser reconciliation tick after their Python state is gone; without a
    # continuous marker the old Account/Settings portal can briefly become
    # visible at the viewport edge between Signing out and the login page.
    # This is visual-only: it adds no callback, sleep, timer, or rerun.
    st.html('<span class="logout-handoff-ui-marker signed-out-portal-quarantine-marker" aria-hidden="true"></span>')
    trace_stage("login-page-render-start")
    render_login_page()
    trace_stage("login-page-render-complete")
    st.stop()

# Warm the local LLM in a daemon thread as soon as a signed-in session exists.
# Mailbox loading continues in parallel, hiding most of the model cold-start cost.
start_ollama_preload()

# Summary actions open as focused standalone browser windows. The signed
# session token remains in the URL, so these routes share the authenticated
# provider client without changing the main AI Summary workspace.
standalone_view = st.query_params.get("view")
if standalone_view in {"original", "draft"}:
    bind_store_to_signed_in_account()
    if standalone_view == "original":
        render_original_email_window(st.query_params.get("uid", ""), folder=FOLDER)
    else:
        render_draft_email_window(st.query_params.get("uid", ""), folder=FOLDER)
    st.stop()

# Bind/load local account data before deciding whether a blocking login surface
# is needed. Returning accounts already have a durable SQLite mailbox cache;
# opening that cache first lets them enter the workspace on this same app run
# instead of painting a short-lived Syncing screen and immediately rerunning.
# That intermediate frame was unnecessary and could strand the browser on the
# stale loader even after the backend had already rendered the Inbox.
bind_store_to_signed_in_account()
# Complete the F5 restore only after the account-scoped Email/Summary stores
# are available. SQLite remains authoritative for Inbox Unread, Summary
# Unviewed, and Spam Detected.
sync_mailmind_attention_refresh_state()

# The first blocking Security pass is durable. If F5/WebSocket replacement
# happened while Analyzing was interrupted, restore that gate before the Inbox
# can mount. This is intentionally separate from full_sync_complete: the full
# mailbox header sync may have completed just before Security hydration lost
# connectivity.
email_store = st.session_state.get("email_store")
security_gate_active = False
if email_store is not None:
    gate_reader = getattr(email_store, "initial_security_gate_active", None)
    if callable(gate_reader):
        security_gate_active = bool(gate_reader(FOLDER))
if security_gate_active:
    st.session_state.initial_security_analysis_incomplete = True
    st.session_state.post_login_loading = True

post_login_loading = bool(st.session_state.get("post_login_loading"))

# Fast path for every returning login: open the local first page BEFORE showing
# a blocking sync surface. ``load_inbox_if_needed`` restores ``full_synced``
# from the durable sync_state without contacting Gmail/Outlook when a completed
# cache already exists. If that succeeds and there is no interrupted Security
# gate to resume, continue directly into the workspace with no extra rerun.
if post_login_loading and not st.session_state.get("initial_sync_error"):
    load_inbox_if_needed(None, folder=FOLDER)
    if st.session_state.get("full_synced") and not security_gate_active:
        st.session_state.post_login_loading = False
        post_login_loading = False
        trace_stage("login-cached-mailbox-fastpath")

# Keep the signed-in workspace hidden only when a first/incomplete mailbox sync
# or an interrupted blocking Security pass genuinely still needs recovery.
if post_login_loading:
    if st.session_state.get("initial_sync_error"):
        post_login_transition_slot.empty()
        render_mailbox_connection_error_page(st.session_state.get("initial_sync_error"))
        st.stop()

    # A returning account with an interrupted Security gate already has a full
    # local mailbox, so show the accurate recovery surface. A genuinely first
    # login still shows the normal mailbox-sync surface.
    if st.session_state.get("full_synced") and security_gate_active:
        render_loading_page(
            title="Analyzing emails",
            subtitle="Resuming the interrupted email security check...",
            target=post_login_transition_slot,
        )
    else:
        render_loading_page(
            title="Syncing your emails",
            subtitle="Syncing Inbox, Spam, and Junk emails...",
            target=post_login_transition_slot,
        )

    # ``load_inbox_if_needed`` is idempotent. On a true first login it prepares
    # the empty local cache for full sync; on a recovery run it returns at once.
    load_inbox_if_needed(None, folder=FOLDER)
    # Only a genuinely first-time/incomplete full sync gets the blocking login
    # Security priority pass. Returning logins reuse saved classifications and
    # let unfinished old-mail work continue through the non-blocking catch-up.
    first_full_sync_needed = not bool(st.session_state.get("full_synced"))
    security_retry_needed = bool(
        st.session_state.get("initial_security_analysis_incomplete")
    )
    run_full_sync_if_needed(None, folder=FOLDER)
    if st.session_state.get("initial_sync_error"):
        # Retire the fixed loading subtree before the error-page rerun so the
        # stale overlay cannot cover the persistent Retry connection surface.
        post_login_transition_slot.empty()
        st.rerun()
    if st.session_state.get("full_synced"):
        if first_full_sync_needed or security_retry_needed:
            st.session_state.initial_security_analysis_incomplete = True
            render_loading_page(
                title="Analyzing emails",
                subtitle="Checking synced emails for security risks and classifications...",
                target=post_login_transition_slot,
            )
            # A redundant provider verification is useful only when resuming an
            # interrupted durable Security gate. The normal first-login full sync
            # has already proved connectivity, so avoid an extra network round-trip.
            st.session_state.initial_security_recovery_check_required = security_retry_needed
            trace_stage("login-security-analysis-start")
            preclassify_pending_spam_security(folder=FOLDER)
            trace_stage("login-security-analysis-complete")
            if st.session_state.get("initial_sync_error"):
                # Provider/network loss while an email is still being hydrated
                # remains a blocking login recovery state. Clear the loading
                # subtree before switching to the persistent recovery surface.
                post_login_transition_slot.empty()
                st.rerun()
            st.session_state.initial_security_analysis_incomplete = False
        st.session_state.post_login_loading = False
        post_login_transition_slot.empty()
        st.rerun()
    st.stop()

# Returning sessions can open the cached first page silently before the sidebar
# is drawn, so its counts and Unread subfilters are already accurate.
load_inbox_if_needed(None, folder=FOLDER)

# If a saved session resumes before its first full sync has completed, keep the
# same full-page loading gate instead of exposing a partially synced workspace.
if not st.session_state.get("full_synced"):
    if st.session_state.get("initial_sync_error"):
        post_login_transition_slot.empty()
        render_mailbox_connection_error_page(st.session_state.get("initial_sync_error"))
        st.stop()

    render_loading_page(
        title="Syncing your emails",
        subtitle="Syncing Inbox, Spam, and Junk emails...",
        target=post_login_transition_slot,
    )
    run_full_sync_if_needed(None, folder=FOLDER)
    if st.session_state.get("initial_sync_error"):
        post_login_transition_slot.empty()
        st.rerun()
    if st.session_state.get("full_synced"):
        st.session_state.initial_security_analysis_incomplete = True
        render_loading_page(
            title="Analyzing emails",
            subtitle="Checking synced emails for security risks and classifications...",
            target=post_login_transition_slot,
        )
        st.session_state.initial_security_recovery_check_required = False
        trace_stage("login-security-analysis-start")
        preclassify_pending_spam_security(folder=FOLDER)
        trace_stage("login-security-analysis-complete")
        if st.session_state.get("initial_sync_error"):
            post_login_transition_slot.empty()
            st.rerun()
        st.session_state.initial_security_analysis_incomplete = False
        post_login_transition_slot.empty()
        st.rerun()
    st.stop()

# The backend is ready for the signed-in workspace. Explicitly retire any
# previous fixed Syncing/Analyzing DOM before mounting sidebar/cards. This is
# the critical stale-loader guard for the case where F5 previously made the
# Inbox appear immediately even though normal login looked stuck.
post_login_transition_slot.empty()

# Mark the signed-in root render as active before any interactive workspace is
# mounted. Timed fragments also execute inline when the full app reruns; this
# durable flag lets them distinguish that inline/root invocation from their
# later timer tick so they can never request another full-app rerun while the
# page is still mounting.
st.session_state.root_render_in_progress = True
trace_stage("workspace-root-start")

# The application sidebar belongs to the signed-in workspace only. Rendering it
# after the local cache is ready prevents stale/zero sidebar counters.
generate_clicked = render_app_sidebar()

# Persist the Generate Summary click immediately, before the Inbox body is
# rendered. A full Inbox render can be interrupted by another Streamlit rerun
# (for example a timed Security catch-up tick). Previously the button event lived
# only in the current script run, so an interrupted render could silently discard
# the first click and make the user click Generate Summary several times.
#
# This is a one-shot intent, not a second generation path. The request is consumed
# below on the stable app root before the heavy Inbox tree is mounted. Repeated
# clicks while the same intent is pending collapse into the same request.
if generate_clicked:
    # The sidebar callback queues the click before the script body starts.  Now
    # that has_checked_emails() has synchronized any mounted checkbox widgets,
    # refresh the snapshot from the authoritative UID set.  This also acts as a
    # compatibility fallback if callbacks are skipped by a Streamlit edge path.
    selected_uids = {
        str(uid).strip()
        for uid in st.session_state.get("checked_uids", set())
        if str(uid).strip()
    }
    if selected_uids:
        was_requested = bool(
            st.session_state.get("manual_summary_generate_requested", False)
        )
        st.session_state.manual_summary_generate_requested = True
        st.session_state.manual_summary_generate_uids = tuple(sorted(selected_uids))
        st.session_state.manual_summary_generate_selected_count = len(selected_uids)
        st.session_state.manual_summary_generate_mode = str(
            st.session_state.get("summary_mode") or "manual"
        )
        if not was_requested:
            mark_generate_click(
                selected_count=st.session_state.manual_summary_generate_selected_count,
                mode=st.session_state.manual_summary_generate_mode,
            )

# Render Summary Settings from the stable app root rather than from inside the
# account popover. This mirrors the root-owned email dialogs and prevents a
# background/fragment rerun from leaving an orphaned blank white dialog layer.
render_summary_settings_dialog()
# A dedicated root-level slot keeps the loading overlay centered across the
# full app, including both sidebar and main content, while blocking clicks.
activity_slot = st.empty()

# A mixed duplicate/new selection starts only after the explicit Summary
# confirmation dialog has been approved. The approval rerun reaches this point
# and mounts the normal blocking manual-summary loading overlay.
resume_deferred_summary_generation()

# If a prior manual-summary preparation was already consumed/aborted but its
# loader ownership flag survived an interrupted rerun, release that orphaned
# backdrop before rendering widgets.  This prevents a stale preparation layer
# from making Inbox checkboxes appear unselectable.
if (
    st.session_state.get("manual_summary_prepare_overlay_owned", False)
    and not st.session_state.get("manual_summary_generate_requested", False)
    and not st.session_state.get("summary_processing", False)
):
    st.session_state.pop("manual_summary_prepare_overlay_owned", None)
    clear_app_loading_state()

# Keep one persistent root-level overlay mounted for any active loading job.
# A mixed manual selection (already summarized + not yet summarized) is a special
# preflight case: the controller must show the existing-summary confirmation
# before any blocking loader is painted.  The sidebar callback has already armed
# the preparation loader at this point, so suppress only that one preparatory
# frame when the saved Summary store proves that at least one selected mailbox
# UID is already represented.  All-new manual requests keep the current loader
# flow unchanged; Auto Summary remains background-only and is not affected.
suppress_mixed_summary_prepare_overlay = False
if (
    st.session_state.get("manual_summary_prepare_overlay_owned", False)
    and st.session_state.get("manual_summary_generate_requested", False)
    and not st.session_state.get("summary_processing", False)
):
    queued_summary_uids = {
        str(uid).strip()
        for uid in st.session_state.get("manual_summary_generate_uids", ())
        if str(uid).strip()
    }
    summary_store = st.session_state.get("summary_store")
    if queued_summary_uids and summary_store is not None:
        try:
            summarized_mailbox_uids = {
                str(uid).strip()
                for uid in summary_store.get_summarized_source_uids(FOLDER)
                if str(uid).strip()
            }
        except Exception:
            # Duplicate detection in start_summary_generation remains authoritative.
            # If the cheap UI precheck cannot read storage, preserve the existing
            # loader behavior rather than changing the generation flow.
            summarized_mailbox_uids = set()
        suppress_mixed_summary_prepare_overlay = bool(
            queued_summary_uids & summarized_mailbox_uids
        )

if not suppress_mixed_summary_prepare_overlay:
    render_active_app_loading_overlay(activity_slot)
# Foreground Cancel controls stay on the stable app root so polling fragments
# cannot remount the buttons/loading card and create visible flicker.
render_draft_cancel_control()
render_summary_cancel_control()
summary_clear = {
    str(uid) for uid in st.session_state.pop("clear_checked_after_summary", [])
    if str(uid)
}
refresh_candidates = {
    str(uid) for uid in st.session_state.pop("clear_checked_after_refresh", [])
    if str(uid)
}

# A manual mailbox Refresh used to clear the entire multi-selection even when
# every selected message was still the same safe, visible Inbox row.  Preserve
# those stable selections across refresh and prune only rows that are no longer
# eligible to remain selected (deleted/unavailable, hidden, or moved to Spam).
# Summary completion still clears exactly the UIDs that were processed.
refresh_clear = set()
if refresh_candidates:
    store = st.session_state.get("email_store")
    for uid in refresh_candidates:
        email = None
        if store is not None:
            try:
                email = store.get_email(FOLDER, uid)
            except Exception:
                email = None
        if (
            not email
            or not bool(email.get("ui_visible", True))
            or bool(email.get("is_spam", False))
            or bool(email.get("provider_spam", False))
        ):
            refresh_clear.add(uid)

if summary_clear:
    # Preserve the existing post-generation behavior: a completed manual Summary
    # clears the selection as one finished batch.
    st.session_state.checked_uids = set()
    for uid in summary_clear:
        st.session_state[f"chk_{uid}"] = False
elif refresh_clear:
    selected_uids = {
        str(uid) for uid in st.session_state.get("checked_uids", set())
        if str(uid)
    }
    selected_uids.difference_update(refresh_clear)
    st.session_state.checked_uids = selected_uids
    for uid in refresh_clear:
        st.session_state[f"chk_{uid}"] = False

# Refresh buttons reset their workspace before search/filter widgets are built.
apply_pending_refresh_resets()
# The old inline deletion notice is superseded by the compact Inbox toast.
st.session_state.pop("email_deletion_notice", None)

# A discarded standalone draft can return to the batch card/tab that opened it.
if st.query_params.get("workspace") == SUMMARY_TAB:
    requested_summary_uid = str(st.query_params.get("summary_uid") or "")
    valid_summary_uids = {
        str(item.get("uid", "")) for item in st.session_state.get("summaries", [])
    }
    st.session_state.active_workspace = SUMMARY_TAB
    if requested_summary_uid in valid_summary_uids:
        st.session_state.selected_summary_uid = requested_summary_uid
    requested_summary_view = str(st.query_params.get("summary_view") or "")
    if requested_summary_view:
        st.session_state.summary_return_tab = requested_summary_view
    for navigation_key in ("workspace", "summary_uid", "summary_view"):
        if navigation_key in st.query_params:
            del st.query_params[navigation_key]

if st.query_params.get("todo_metric"):
    st.session_state.active_workspace = TODO_TAB

if st.session_state.pop("switch_to_summary", False):
    st.session_state.active_workspace = SUMMARY_TAB

# Backward compatibility for sessions saved before Spam became a main tab.
if (
    st.session_state.active_workspace == INBOX_TAB
    and str(st.session_state.get("inbox_filter") or "all").casefold() == "spam"
):
    st.session_state.active_workspace = SPAM_TAB
if st.session_state.active_workspace not in {INBOX_TAB, SPAM_TAB, SUMMARY_TAB, TODO_TAB}:
    st.session_state.active_workspace = INBOX_TAB
active_workspace = st.session_state.active_workspace
trace_stage("workspace-selected", target=active_workspace)

# Consume a queued manual Generate Summary intent before rendering the Inbox.
# ``start_summary_generation`` resolves selected UIDs from SQLite, so the current
# cached page is only a fallback. Keeping the intent set until that call returns
# makes the click durable across an interrupted Streamlit run; if this run is
# cancelled before the call completes, the next stable run retries the same
# one-shot request automatically instead of requiring another user click.
if (
    active_workspace == INBOX_TAB
    and st.session_state.get("manual_summary_generate_requested", False)
):
    generate_list_source = (
        list(st.session_state.get("search_results", []))
        if bool(st.session_state.get("search_active", False))
        else list(st.session_state.get("emails", []))
    )
    queued_uids = tuple(
        str(uid).strip()
        for uid in st.session_state.get("manual_summary_generate_uids", ())
        if str(uid).strip()
    )

    # The sidebar callback already arms the preparation overlay before this
    # root run starts.  Dispatch directly here; a second preparatory rerun made
    # the request vulnerable to repeated widget reruns before the controller
    # could launch the worker.
    trace_stage(
        "manual-summary-start-dispatch",
        selected_count=len(queued_uids),
    )
    generate_handled = start_summary_generation(
        generate_list_source,
        folder=FOLDER,
        selected_uids_override=(queued_uids or None),
    )
    # The request stays durable only until start_summary_generation returns.  If
    # this root run is interrupted before/during that call, Streamlit never
    # reaches these clears and the click is retried automatically next run.
    # Once the controller has returned, consume the one-shot intent exactly once.
    st.session_state.manual_summary_generate_requested = False
    st.session_state.pop("manual_summary_generate_uids", None)
    st.session_state.pop("manual_summary_generate_selected_count", None)
    st.session_state.pop("manual_summary_generate_mode", None)
    owned_prepare_overlay = bool(
        st.session_state.pop("manual_summary_prepare_overlay_owned", False)
    )
    if generate_handled and st.session_state.get("summary_processing", False):
        # Keep the existing workspace mounted and paint the already-defined
        # Summary loading overlay in this same root run. A full rerun here used
        # to tear down the partially rendered Inbox before the next run could
        # mount the loader, which produced a short white/stale flash after the
        # Generate Summary click. The worker, cancellation state, Security gate,
        # duplicate handling, and monitor flow are unchanged.
        render_active_app_loading_overlay(activity_slot)
        render_summary_cancel_control()
    elif owned_prepare_overlay:
        # The preparation overlay belongs only to this manual Generate request.
        # Duplicate-only, blocked, or otherwise non-starting outcomes must not
        # leave a stale global loader behind. Mixed-selection confirmation already
        # clears it inside the controller; this cleanup is intentionally idempotent.
        clear_app_loading_state()

# A finished background draft is only promoted to dialog state on this stable
# full-app/root run. This avoids opening a Streamlit dialog portal from a timer
# fragment, which can intermittently leave the browser on a blank white layer.
promote_pending_draft_dialog(st.session_state)

# Task Actions uses a durable UID only to stay protected from background reruns.
# When an action inside the dialog explicitly requests a close, consume that
# one-shot request before deciding whether background monitors are paused. This
# reproduces the proven Email-Assistant_69 behavior: Update/Mark as Completed
# closes the editor on the next full-app rerun instead of remounting it.
if bool(st.session_state.pop("todo_task_actions_close_requested", False)):
    st.session_state.pop("todo_dialog_uid", None)

# Root-owned dialogs/confirmations pause every timer/background monitor. The monitors
# themselves are mounted only after the current workspace below has rendered, so
# a timer-driven full-app rerun cannot interrupt the page before its main content
# is present. This is especially important for long Security catch-up sessions.
background_monitors_paused = _background_monitor_pause_requested()

# Transition-based task alerts are evaluated once per stable app run. Durable
# markers prevent Due Today / Overdue alerts from replaying on reruns or login.
publish_task_deadline_alerts()
queue_security_catchup_background_toast(folder=FOLDER)

# Informational notices are global overlay toasts, so background Security, Auto
# Summary, and task-deadline feedback remains visible on every workspace.
render_summary_toasts()
render_inbox_toasts()
render_todo_toasts()
render_summary_confirmation()
trace_stage("workspace-render-start", target=active_workspace)

if active_workspace == INBOX_TAB:
    inbox_actions, list_source = render_inbox_tab(
        activity_slot, folder=FOLDER, spam_view=False
    )
    handle_inbox_actions(inbox_actions, activity_slot, folder=FOLDER)
elif active_workspace == SPAM_TAB:
    if str(st.session_state.get("inbox_filter") or "").casefold() != "spam":
        st.session_state.inbox_filter = "spam"
        st.session_state.inbox_offset = 0
        st.session_state.inbox_search_offset = 0
        st.session_state.inbox_loaded_view_signature = None
    inbox_actions, _list_source = render_inbox_tab(
        activity_slot, folder=FOLDER, spam_view=True
    )
    handle_inbox_actions(inbox_actions, activity_slot, folder=FOLDER)
elif active_workspace == SUMMARY_TAB:
    _summary_render_started_at = mark_summary_render_start()
    render_summary_tab()
    mark_summary_render_visible(_summary_render_started_at)
else:
    render_todo_tab()

trace_stage("workspace-render-complete", target=active_workspace)

# Action dialogs are mounted once from the app root, not from inside a reader
# fragment. This keeps Original Email, Draft Email, and Task Actions stable
# across background/full-app reruns. Task Actions also acts as a foreground
# interaction guard: mailbox/security/auto-summary maintenance stays paused
# until the user dismisses the dialog, then resumes on the stable root rerun.
render_active_email_dialog()
render_task_actions_dialog()

# Render the global bell after the active workspace/dialogs.
render_notification_center()
trace_stage("overlays-render-complete")

# Background processors are intentionally mounted only after the current
# workspace has been painted. Re-evaluate dialog/navigation state *now* because
# a user may have opened an email/dialog during the workspace render above.
# This closes the one-render race where a freshly opened Security email dialog
# could still inherit monitors that were considered safe before its button ran.
background_monitors_paused = _background_monitor_pause_requested()
foreground_navigation_guard = bool(
    st.session_state.get("foreground_navigation_guard", False)
)

# External maintenance (mailbox polling, Security catch-up, and Auto Summary
# scheduling) must not compete with a foreground blocking job or a user
# navigation render. A competing timer/full-app rerun can briefly unmount/remount
# the workspace and show up as a completely blank white Streamlit frame.
# Foreground job monitors remain active so their own progress/completion can
# still update normally.
summary_processing = bool(st.session_state.get("summary_processing"))
summary_job_origin = str(st.session_state.get("summary_job_origin") or "manual")
auto_summary_processing = bool(summary_processing and summary_job_origin == "auto")
manual_summary_processing = bool(summary_processing and not auto_summary_processing)
foreground_job_active = bool(
    st.session_state.get("app_loading_active")
    or manual_summary_processing
    or st.session_state.get("draft_processing")
)
_new_mail_security_future = st.session_state.get("new_mail_security_refinement_future")
new_mail_security_active = bool(
    _new_mail_security_future is not None and not _new_mail_security_future.done()
)
# NEW-mail Security owns Ollama ahead of lower-priority mailbox catch-up and Auto
# Summary, but its completion monitor stays mounted so the UI remains responsive.
maintenance_paused = bool(
    background_monitors_paused
    or foreground_job_active
    # Auto Summary may use the local model in the background, so lower-priority
    # provider/Security maintenance still yields to it. Unlike a foreground job,
    # this does NOT block or cover user interactions.
    or auto_summary_processing
    or foreground_navigation_guard
    or foreground_interaction_is_settling()
)
if new_mail_security_active:
    maintenance_paused = True
trace_stage(
    "maintenance-evaluated",
    background_paused=bool(background_monitors_paused),
    foreground_job=bool(foreground_job_active),
    navigation_guard=bool(foreground_navigation_guard),
    maintenance_paused=bool(maintenance_paused),
    new_mail_security=bool(new_mail_security_active),
)

# Timer fragments must stay MOUNTED during the one-render foreground
# navigation guard. Their own root-render/generation gates keep them inert while
# the click/rerun is being painted, then the same mounted fragment wakes on its
# next timer tick after the guard is cleared below. If we skip mounting the
# fragment entirely, no timer survives to finish NEW-mail Security or resume
# low-priority catch-up after Refresh/Next/Previous/tab/filter actions.
if not background_monitors_paused and not foreground_job_active:
    trace_stage("monitor-new-mail-security-mount")
    monitor_new_mail_security_refinement(folder=FOLDER)

    # Keep the lightweight provider message-count monitor alive even while one
    # NEW-mail contextual Security request owns Ollama. This lets later arrivals
    # be detected and queued immediately without allowing provider hydration/DB
    # publication to race the active Security worker. Lower-priority catch-up and
    # Auto Summary still yield until NEW-mail Security is clear.
    trace_stage("monitor-mailbox-mount")
    monitor_mailbox_changes(folder=FOLDER)
    if not new_mail_security_active:
        trace_stage("monitor-security-catchup-mount")
        monitor_security_catchup(folder=FOLDER)
        trace_stage("monitor-auto-summary-mount")
        monitor_auto_summary_queue(folder=FOLDER)

# Non-fragment processors can perform provider/DB work immediately, so unlike
# timer fragments they remain behind the full maintenance pause (including the
# one-render navigation guard).
if not maintenance_paused:
    trace_stage("maintenance-process-start")
    # Hidden genuinely NEW mail is the highest-priority maintenance job. Retry
    # any incomplete full-message Security before normal mailbox sync, catch-up,
    # or Auto Summary can consume provider/model capacity.
    trace_stage("process-new-mail-security")
    if process_pending_new_mail_security(folder=FOLDER):
        st.rerun()
    trace_stage("process-mailbox-sync")
    process_pending_mailbox_sync(None, folder=FOLDER)
    trace_stage("process-auto-summary")
    if process_pending_auto_summary(folder=FOLDER):
        st.rerun()
    trace_stage("maintenance-process-complete")

if not background_monitors_paused:
    # These monitors own the active foreground jobs and therefore must keep
    # polling while the blocking overlay is visible.
    trace_stage("monitor-draft-generation-mount")
    monitor_draft_generation(activity_slot)
    trace_stage("monitor-summary-generation-mount")
    monitor_summary_generation(activity_slot, folder=FOLDER)

trace_stage("background-monitors-mounted")

# The stable root page is fully mounted. Timer fragments may resume on their
# next scheduled tick. A foreground navigation guard lasts for exactly this one
# stabilizing render, then clears automatically.
st.session_state.root_render_in_progress = False
st.session_state.pop("foreground_navigation_guard", None)
# Snapshot the completed render so the next F5 restores the same attention
# state instead of treating an unread message as viewed.
sync_mailmind_attention_refresh_state()
trace_stage("root-finalized")
complete_app_run()
