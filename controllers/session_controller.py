import streamlit as st

from storage.email_store import EmailStore, normalize_account_email
from storage.session_store import get_session
from storage.summary_store import SUMMARY_FOLDER, SummaryStore


# Add a default only when the session key does not exist.
def _init_state(key, default):
    if key not in st.session_state:
        st.session_state[key] = default


# Prepare the Streamlit session values used by the app.
def initialize_session_state():
    defaults = {
        "logged_in": False,
        "emails": [],
        "selected_uid": None,
        "inbox_loaded": False,
        "inbox_offset": 0,
        "inbox_has_more": False,
        "inbox_total": 0,
        "inbox_all_total": 0,
        "email_bodies": {},
        "email_validation_cache": {},
        "checked_uids": set(),
        "summary_mode": "manual",
        "batch_summary_enabled": False,
        "auto_summary_enabled": False,
        "auto_summary_type_choice": "Individual",
        "auto_summary_batch_started_at": 0.0,
        "auto_summary_batch_deadline": 0.0,
        "pending_auto_summary_uids": set(),
        "pending_auto_individual_arrivals": {},
        "pending_auto_summary_arrivals": {},
        "pending_auto_summary_lifecycle": {},
        "pending_provider_moved_to_inbox_uids": set(),
        "pending_provider_moved_to_spam_uids": set(),
        "pending_security_hydration_uids": set(),
        "security_catchup_future": None,
        "security_catchup_executor": None,
        "security_catchup_progress": None,
        "security_catchup_batch_size": 0,
        "security_catchup_session_total": 0,
        "security_catchup_remaining": 0,
        "security_catchup_unsafe_count": 0,
        "security_catchup_category_counts": {},
        "security_catchup_completion_notified": False,
        "security_catchup_background_toast_shown": False,
        "security_catchup_completed_at": 0.0,
        "security_catchup_next_at": 0.0,
        "security_catchup_monitor_seen_generation": -1,
        "auto_summary_queue_updated_at": 0.0,
        "auto_summary_not_before": 0.0,
        "auto_summary_start_requested": False,
        "auto_summary_retry_after": 0.0,
        "auto_summary_monitor_seen_generation": -1,
        "summary_job_origin": "manual",
        "search_active": False,
        "search_results": [],
        "search_total": 0,
        "inbox_search_offset": 0,
        "inbox_search_page_size": 10,
        "full_synced": False,
        "full_sync_attempted": False,
        "initial_sync_error": "",
        "initial_security_analysis_incomplete": False,
        "provider_connection_state": "connected",
        "provider_connection_error": "",
        "provider_connection_notice_active": False,
        "loading": False,
        "inbox_search_submit": False,
        "inbox_search_clear": False,
        "last_mail_check": 0.0,
        "new_mail_count": 0,
        "email_deletion_notice": "",
        "inbox_toasts": [],
        "summary_toasts": [],
        "todo_toasts": [],
        "pending_new_mail_notification_uids": set(),
        "new_mail_security_recovery_uids": set(),
        "summary_pending_confirmation": None,
        "notification_center_filter": "All",
        "notification_center_open": False,
        "notification_center_expanded": False,
        "notification_center_root_reconcile": False,
        "notification_store": None,
        "ollama_notice_signature": "",
        "mailbox_monitor_busy": False,
        "mailbox_monitor_seen_generation": -1,
        "app_run_generation": 0,
        # UI-only coordination for expensive foreground reruns. Explicit
        # defaults keep rapid-click guards deterministic after login/refresh and
        # prevent stale values from leaking across account switches.
        "root_render_in_progress": False,
        "foreground_navigation_guard": False,
        "foreground_ui_settle_until": 0.0,
        "foreground_action_stamps": {},
        "inbox_pending_page_direction": "",
        "summary_pending_page_direction": "",
        "todo_pending_page_direction": "",
        "inbox_list_scroll_reset_pending": False,
        "summary_list_scroll_reset_pending": False,
        "todo_list_scroll_reset_pending": False,
        "inbox_list_scroll_epoch": 0,
        "summary_list_scroll_epoch": 0,
        "todo_list_scroll_epoch": 0,
        "mailbox_sync_in_progress": False,
        "mailbox_sync_future": None,
        "mailbox_sync_executor": None,
        "mailbox_sync_account": "",
        "pending_mailbox_remote_count": None,
        "pending_mailbox_detected_at": 0.0,
        "pending_mailbox_location_change": False,
        "mailbox_location_count_signature": None,
        "last_mail_reconcile": 0.0,
        "inbox_refresh_requested": False,
        "inbox_refresh_reset_pending": False,
        "summary_refresh_reset_pending": False,
        "summaries": [],
        "selected_summary_uid": None,
        "summary_processing": False,
        "summary_future": None,
        "summary_cancel_token": None,
        "summary_cancel_requested": False,
        "draft_processing": False,
        "draft_cancel_requested": False,
        "draft_future": None,
        "draft_executor": None,
        "draft_processing_uid": "",
        "draft_dialog_pending_uid": "",
        "draft_prepare_error_uid": "",
        "draft_prepare_error": "",
        "summary_job_uids": [],
        "summary_progress": None,
        "summary_deferred_ready": False,
        "deferred_summary_request": None,
        "active_inbox_toast_on_dismiss": "",
        "open_summary_tab": False,
        "active_workspace": "inbox",
        "summary_filter": "all",
        "summary_task_filter": None,
        "summary_unread_only": False,
        "summary_type_filter": None,
        "summary_status_filter": None,
        "summary_priority_filter": None,
        "summary_arrange_by": "date",
        "summary_sort_order": "newest",
        "summary_filter_popover_version": 0,
        "summary_offset": 0,
        "summary_page_size": 10,
        "todo_search_query": "",
        "todo_status_filter": None,
        "todo_priority_filter": None,
        "todo_deadline_filter": None,
        "todo_sort_by": "due_soonest",
        "todo_filter_popover_version": 0,
        "todo_offset": 0,
        "todo_page_size": 10,
        "switch_to_summary": False,
        "clear_checked_after_summary": [],
        "clear_checked_after_refresh": [],
        "new_email_uids": set(),
        "restored_email_uids": set(),
        "inbox_filter": "all",
        "inbox_arrange_by": "date",
        "inbox_sort_order": "newest",
        "inbox_filter_popover_version": 0,
        "spam_category_filter": "all",
        "spam_detected_only": False,
        "spam_reviewed_pinned_uid": "",
        "inbox_loaded_view_signature": None,
        "login_authenticating": False,
        "login_error": "",
        "login_email_error": "",
        "post_login_loading": False,
        "app_loading_active": False,
        "app_loading_title": "Please wait...",
        "app_loading_subtitle": "Loading...",
        "app_loading_detail": "",
        "login_submit_requested": False,
        "login_manual_mode": False,
        "suppress_login_autofill": True,
        "pending_login_email": "",
        "pending_login_password": "",
        "pending_login_server": "",
        "pending_login_port": 993,
        "microsoft_login_active": False,
        "microsoft_login_error": "",
        "microsoft_login_redirect_url": "",
        "profile_image_url": "",
    }
    for key, default in defaults.items():
        _init_state(key, default)

    # Backward-compatible migration from the old mutually-exclusive Spam
    # "newly_detected" pseudo-category to the independent Detected toggle.
    if str(st.session_state.get("spam_category_filter") or "all").casefold() == "newly_detected":
        st.session_state.spam_category_filter = "all"
        st.session_state.spam_detected_only = True


# Clear inbox, search, and reader state after an account change.
def _reset_mailbox_state_for_account():
    defaults = {
        "emails": [],
        "selected_uid": None,
        "inbox_loaded": False,
        "inbox_offset": 0,
        "inbox_has_more": False,
        "inbox_total": 0,
        "inbox_all_total": 0,
        "email_bodies": {},
        "email_validation_cache": {},
        "checked_uids": set(),
        "summary_mode": "manual",
        "batch_summary_enabled": False,
        "auto_summary_enabled": False,
        "auto_summary_type_choice": "Individual",
        "auto_summary_batch_started_at": 0.0,
        "auto_summary_batch_deadline": 0.0,
        "pending_auto_summary_uids": set(),
        "pending_auto_individual_arrivals": {},
        "pending_auto_summary_arrivals": {},
        "pending_auto_summary_lifecycle": {},
        "pending_provider_moved_to_inbox_uids": set(),
        "pending_provider_moved_to_spam_uids": set(),
        "pending_security_hydration_uids": set(),
        "security_catchup_future": None,
        "security_catchup_executor": None,
        "security_catchup_progress": None,
        "security_catchup_batch_size": 0,
        "security_catchup_session_total": 0,
        "security_catchup_remaining": 0,
        "security_catchup_unsafe_count": 0,
        "security_catchup_category_counts": {},
        "security_catchup_completion_notified": False,
        "security_catchup_background_toast_shown": False,
        "security_catchup_completed_at": 0.0,
        "security_catchup_next_at": 0.0,
        "security_catchup_monitor_seen_generation": -1,
        "auto_summary_queue_updated_at": 0.0,
        "auto_summary_not_before": 0.0,
        "auto_summary_start_requested": False,
        "auto_summary_retry_after": 0.0,
        "auto_summary_monitor_seen_generation": -1,
        "summary_job_origin": "manual",
        "search_active": False,
        "search_results": [],
        "search_total": 0,
        "inbox_search_offset": 0,
        "inbox_search_page_size": 10,
        "full_synced": False,
        "full_sync_attempted": False,
        "initial_sync_error": "",
        "initial_security_analysis_incomplete": False,
        "provider_connection_state": "connected",
        "provider_connection_error": "",
        "provider_connection_notice_active": False,
        "loading": False,
        "last_mail_check": 0.0,
        "new_mail_count": 0,
        "email_deletion_notice": "",
        "inbox_toasts": [],
        "summary_toasts": [],
        "todo_toasts": [],
        "pending_new_mail_notification_uids": set(),
        "new_mail_security_recovery_uids": set(),
        "summary_pending_confirmation": None,
        "notification_center_open": False,
        "notification_center_expanded": False,
        "notification_center_root_reconcile": False,
        "ollama_notice_signature": "",
        "mailbox_monitor_busy": False,
        "mailbox_monitor_seen_generation": -1,
        "app_run_generation": 0,
        # UI-only coordination for expensive foreground reruns. Explicit
        # defaults keep rapid-click guards deterministic after login/refresh and
        # prevent stale values from leaking across account switches.
        "root_render_in_progress": False,
        "foreground_navigation_guard": False,
        "foreground_ui_settle_until": 0.0,
        "foreground_action_stamps": {},
        "inbox_pending_page_direction": "",
        "summary_pending_page_direction": "",
        "todo_pending_page_direction": "",
        "inbox_list_scroll_reset_pending": False,
        "summary_list_scroll_reset_pending": False,
        "todo_list_scroll_reset_pending": False,
        "inbox_list_scroll_epoch": 0,
        "summary_list_scroll_epoch": 0,
        "todo_list_scroll_epoch": 0,
        "mailbox_sync_in_progress": False,
        "mailbox_sync_future": None,
        "mailbox_sync_executor": None,
        "mailbox_sync_account": "",
        "pending_mailbox_remote_count": None,
        "pending_mailbox_detected_at": 0.0,
        "pending_mailbox_location_change": False,
        "mailbox_location_count_signature": None,
        "last_mail_reconcile": 0.0,
        "inbox_refresh_requested": False,
        "inbox_refresh_reset_pending": False,
        "summary_refresh_reset_pending": False,
        "summaries": [],
        "selected_summary_uid": None,
        "summary_processing": False,
        "summary_future": None,
        "summary_cancel_token": None,
        "summary_cancel_requested": False,
        "draft_processing": False,
        "draft_cancel_requested": False,
        "draft_future": None,
        "draft_executor": None,
        "draft_processing_uid": "",
        "draft_dialog_pending_uid": "",
        "draft_prepare_error_uid": "",
        "draft_prepare_error": "",
        "summary_job_uids": [],
        "summary_progress": None,
        "summary_deferred_ready": False,
        "deferred_summary_request": None,
        "active_inbox_toast_on_dismiss": "",
        "open_summary_tab": False,
        "active_workspace": "inbox",
        "summary_filter": "all",
        "summary_task_filter": None,
        "summary_unread_only": False,
        "summary_type_filter": None,
        "summary_status_filter": None,
        "summary_priority_filter": None,
        "summary_arrange_by": "date",
        "summary_sort_order": "newest",
        "summary_filter_popover_version": 0,
        "summary_offset": 0,
        "summary_page_size": 10,
        "todo_search_query": "",
        "todo_status_filter": None,
        "todo_priority_filter": None,
        "todo_deadline_filter": None,
        "todo_sort_by": "due_soonest",
        "todo_filter_popover_version": 0,
        "todo_offset": 0,
        "todo_page_size": 10,
        "switch_to_summary": False,
        "clear_checked_after_summary": [],
        "clear_checked_after_refresh": [],
        "new_email_uids": set(),
        "restored_email_uids": set(),
        "inbox_filter": "all",
        "inbox_arrange_by": "date",
        "inbox_sort_order": "newest",
        "inbox_filter_popover_version": 0,
        "spam_category_filter": "all",
        "spam_detected_only": False,
        "spam_reviewed_pinned_uid": "",
        "inbox_loaded_view_signature": None,
        "login_authenticating": False,
        "login_error": "",
        "login_email_error": "",
        "post_login_loading": False,
        "app_loading_active": False,
        "app_loading_title": "Please wait...",
        "app_loading_subtitle": "Loading...",
        "app_loading_detail": "",
        "login_submit_requested": False,
        "login_manual_mode": False,
        "suppress_login_autofill": True,
        "pending_login_email": "",
        "pending_login_password": "",
        "pending_login_server": "",
        "pending_login_port": 993,
        "microsoft_login_active": False,
        "microsoft_login_error": "",
        "microsoft_login_redirect_url": "",
        "profile_image_url": "",
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def apply_pending_refresh_resets() -> None:
    # Apply toolbar refresh resets before any search/filter widgets render.
    if st.session_state.pop("inbox_refresh_reset_pending", False):
        st.session_state.inbox_search_query = ""
        st.session_state.inbox_search_submit = False
        st.session_state.inbox_search_clear = False
        st.session_state.search_active = False
        st.session_state.search_results = []
        st.session_state.search_total = 0
        st.session_state.inbox_search_offset = 0
        st.session_state.inbox_offset = 0
        if str(st.session_state.get("active_workspace") or "").casefold() == "spam":
            st.session_state.inbox_filter = "spam"
            st.session_state.spam_category_filter = "all"
            st.session_state.spam_detected_only = False
        else:
            st.session_state.inbox_filter = "all"
        st.session_state.inbox_arrange_by = "date"
        st.session_state.inbox_sort_order = "newest"
        st.session_state.inbox_loaded_view_signature = None
        st.session_state.selected_uid = None
        st.session_state.inbox_filter_popover_version = (
            int(st.session_state.get("inbox_filter_popover_version", 0)) + 1
        )

    if st.session_state.pop("summary_refresh_reset_pending", False):
        st.session_state.summary_search_query = ""
        st.session_state.summary_filter = "all"
        st.session_state.summary_task_filter = None
        st.session_state.summary_unread_only = False
        st.session_state.summary_type_filter = None
        st.session_state.summary_status_filter = None
        st.session_state.summary_priority_filter = None
        st.session_state.summary_arrange_by = "date"
        st.session_state.summary_sort_order = "newest"
        st.session_state.summary_offset = 0
        st.session_state.summary_filter_popover_version = (
            int(st.session_state.get("summary_filter_popover_version", 0)) + 1
        )


def _restore_persisted_summary_preferences(store: EmailStore) -> None:
    # Summary Settings are account preferences, not transient workspace state.
    # Restore only the two explicit user choices; generation queues, futures,
    # selections, and other runtime state remain session-local.
    generation_mode = store.get_user_preference(
        "summary_generation_mode", "Manual"
    ).strip().casefold()
    summary_type = store.get_user_preference(
        "summary_type", "Individual"
    ).strip().casefold()

    auto_enabled = generation_mode == "automatic"
    normalized_type = "Batch" if summary_type == "batch" else "Individual"
    normalized_mode = "batch" if normalized_type == "Batch" else "manual"

    st.session_state.auto_summary_enabled = auto_enabled
    st.session_state.auto_summary_type_choice = normalized_type
    st.session_state.summary_mode = normalized_mode
    st.session_state.batch_summary_enabled = normalized_type == "Batch"
    st.session_state.summary_mode_choice = (
        "Batch Summary" if normalized_type == "Batch" else "Individual Summary"
    )


# Bind the shared database store to the signed-in email account.
def bind_store_to_signed_in_account():
    account_email = normalize_account_email(
        st.session_state.get("email_address", "")
    )
    current_store = st.session_state.get("email_store")
    current_summary_store = st.session_state.get("summary_store")

    if (
        current_store is not None
        and current_store.account_email == account_email
        and current_summary_store is not None
        and current_summary_store.account_email == account_email
    ):
        return

    if current_store is not None:
        try:
            current_store.close()
        except Exception:
            pass
    if current_summary_store is not None:
        try:
            current_summary_store.close()
        except Exception:
            pass

    # Preserve the OAuth/new-account login gate across the account-state reset.
    # ``process_microsoft_callback`` intentionally sets post_login_loading=True so
    # an empty/new mailbox skips the foreground first-page provider fetch and goes
    # straight to the root-owned Syncing surface.  The generic account reset used
    # to clear that flag here, which made a newly selected account perform a remote
    # refresh before any signed-in UI was mounted; a slow provider call therefore
    # left only the page background visible after login.  Returning saved sessions
    # still keep their existing False value and retain the cached-mailbox fast path.
    preserve_post_login_loading = bool(
        st.session_state.get("post_login_loading", False)
    )
    _reset_mailbox_state_for_account()
    st.session_state.post_login_loading = preserve_post_login_loading

    st.session_state.email_store = EmailStore(account_email=account_email)
    st.session_state.summary_store = SummaryStore(account_email=account_email)
    st.session_state.active_store_account = account_email
    _restore_persisted_summary_preferences(st.session_state.email_store)
    st.session_state.summaries = st.session_state.summary_store.load_all(SUMMARY_FOLDER)
    # Keep the AI Summary reader empty until the user explicitly opens a card.
    st.session_state.selected_summary_uid = None


# Restore the live login after a browser refresh.
def restore_saved_session():
    if not st.session_state.logged_in:
        token = st.query_params.get("s")
        saved = get_session(token)
        if saved:
            st.session_state.imap_client = saved["client"]
            st.session_state.logged_in = True
            st.session_state.email_address = saved["email_address"]
            st.session_state.session_token = token
            # This is a returning browser session. Open the saved local inbox
            # directly instead of showing the full post-login loading screen.
            st.session_state.post_login_loading = False
        elif token:
            st.query_params.clear()




def _normalized_uid_set(values) -> set[str]:
    return {str(uid) for uid in (values or set()) if str(uid)}


def sync_mailmind_attention_refresh_state() -> None:
    """Preserve MailMind attention markers across browser refreshes.

    Inbox ``Unread`` is now durable in ``emails.db`` via
    ``emails.mailmind_unread``. AI Summary ``Unviewed`` and Spam ``Detected``
    already use durable database flags. The signed server-side session snapshot
    remains only as a one-time compatibility seed for installs upgrading from
    the older session-only Inbox Unread behavior.

    This is MailMind UI/view-state persistence only. It never changes the
    provider Seen flag, Security classification/routing, Summary generation, or
    Reply Draft behavior.
    """
    if not st.session_state.get("logged_in"):
        return

    token = str(st.session_state.get("session_token") or "").strip()
    if not token:
        return
    saved = get_session(token)
    if saved is None:
        return

    bound_token = str(
        st.session_state.get("_mailmind_attention_refresh_token") or ""
    ).strip()
    fresh_streamlit_session = bound_token != token
    if fresh_streamlit_session:
        # Account binding intentionally resets transient state, so defer all
        # database-backed restoration until the account stores are open.
        st.session_state._mailmind_attention_refresh_token = token
        st.session_state._mailmind_attention_restore_pending = True

    email_store = st.session_state.get("email_store")
    summary_store = st.session_state.get("summary_store")
    stores_ready = email_store is not None and summary_store is not None

    if not stores_ready:
        # Keep the legacy snapshot current while the old session-only mechanism
        # still exists in memory. On a fresh F5, wait until after account bind so
        # the reset cannot overwrite restored state.
        if not fresh_streamlit_session:
            saved["mailmind_unread_uids"] = _normalized_uid_set(
                st.session_state.get("new_email_uids", set())
            )
        return

    restore_pending = bool(
        st.session_state.pop("_mailmind_attention_restore_pending", False)
    )

    # Migrate the old session-only Inbox Unread set exactly once, then make
    # SQLite authoritative. This is the critical F5 fix: a fresh Streamlit
    # Session State can start empty without consuming the unread markers.
    legacy_unread = _normalized_uid_set(
        st.session_state.get("new_email_uids", set())
    )
    if restore_pending:
        legacy_unread.update(
            _normalized_uid_set(saved.get("mailmind_unread_uids", set()))
        )
    email_store.initialize_mailmind_unread_state("ALL_MAIL", legacy_unread)
    durable_unread = email_store.get_mailmind_unread_uids("ALL_MAIL")
    if durable_unread != _normalized_uid_set(
        st.session_state.get("new_email_uids", set())
    ):
        st.session_state.new_email_uids = set(durable_unread)
        st.session_state.inbox_loaded_view_signature = None

    if restore_pending:
        # Summary Unviewed is already durable in summaries.db. Reapply only the
        # compatibility snapshot so older in-memory state survives the upgrade.
        saved_unviewed = _normalized_uid_set(
            saved.get("mailmind_unviewed_summary_uids", set())
        )
        if saved_unviewed:
            summary_store.mark_unread_many(SUMMARY_FOLDER, saved_unviewed)

        # Spam Detected is also durable in emails.db and is independent of the
        # email read state. Reapply only previously-unreviewed compatibility UIDs.
        saved_detected = _normalized_uid_set(
            saved.get("mailmind_detected_security_uids", set())
        )
        if saved_detected:
            email_store.mark_security_unreviewed("ALL_MAIL", saved_detected)

        st.session_state.summaries = summary_store.load_all(SUMMARY_FOLDER)
        st.session_state.inbox_loaded_view_signature = None

    # Keep compatibility snapshots current, but the database remains the source
    # of truth for all three attention states.
    current_unread = email_store.get_mailmind_unread_uids("ALL_MAIL")
    if current_unread != _normalized_uid_set(
        st.session_state.get("new_email_uids", set())
    ):
        st.session_state.new_email_uids = set(current_unread)
        st.session_state.inbox_loaded_view_signature = None

    current_summaries = summary_store.load_all(SUMMARY_FOLDER)
    current_unviewed = {
        str(item.get("uid"))
        for item in current_summaries
        if str(item.get("uid")) and not bool(item.get("is_read", False))
    }
    current_detected = email_store.get_security_unreviewed_uids("ALL_MAIL")

    saved["mailmind_unread_uids"] = set(current_unread)
    saved["mailmind_unviewed_summary_uids"] = set(current_unviewed)
    saved["mailmind_detected_security_uids"] = set(current_detected)
    st.session_state.summaries = current_summaries


# Backward-compatible alias for any older patch/import still using the first
# Inbox-only helper name.
sync_mailmind_unread_refresh_state = sync_mailmind_attention_refresh_state
