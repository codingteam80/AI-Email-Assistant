import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import streamlit as st

from config import (
    AUTO_BATCH_WAIT_SECONDS,
    MAX_EMAILS_FETCH,
    MAILBOX_MONITOR_FRAGMENT_SECONDS,
    MAILBOX_POLL_SECONDS,
    MAILBOX_RECONCILE_SECONDS,
    MAILBOX_SYNC_PAGE_SIZE,
    NEW_MAIL_SECURITY_FRAGMENT_SECONDS,
    NEW_MAIL_SECURITY_RETRY_SECONDS,
    SECURITY_CATCHUP_BATCH_SIZE,
    SECURITY_CATCHUP_COOLDOWN_SECONDS,
    SECURITY_CATCHUP_FRAGMENT_SECONDS,
    SECURITY_ALERT_DETAIL_LIMIT,
    SECURITY_LLM_LOCK_TIMEOUT_SECONDS,
)
from controllers.deletion_controller import apply_confirmed_deletions
from services.deletion_detection_service import reconcile_folder
from services.ai_service import classify_email_security_batch, get_ollama_status
from services.spam_detection_service import detect_spam
from services.security_input_service import normalize_security_input
from services.security.refinement_policy import should_contextually_refine_security
from services.security_trace_service import security_trace_mode, trace_security_detection
from services.restoration_service import classify_restored_arrivals, same_message_identity
from services.mailbox_lifecycle_service import detect_cross_uid_provider_moves
from services.summary_eligibility_service import evaluate_summary_eligibility
from services.ui_interaction_service import arm_foreground_interaction, foreground_interaction_is_settling
from services.white_stale_trace_service import trace_action
from services.network_status_service import (
    is_network_error,
    mark_provider_connection_issue,
    mark_provider_connection_ok,
    provider_error_message,
)
from services.email_service import (
    get_full_email,
    load_cached_inbox,
    refresh_inbox,
    refresh_security_changes,
    sync_all_inbox,
)
from ui.inbox_notifications import push_inbox_toast
from ui.notification_center import record_notification
from ui.loading import (
    clear_app_loading_overlay,
    clear_app_loading_state,
    render_app_loading_overlay,
    set_app_loading_state,
    update_app_loading_state,
)


# Show the shared loading overlay in the workspace.
def start_sidebar_activity(activity_slot, text: str, value: float = 0.05):
    if activity_slot is None:
        return None
    payload = {"slot": activity_slot}
    detail = f"{int(max(0.0, min(value, 1.0)) * 100)}%" if value > 0 else ""
    set_app_loading_state("Please wait...", text, detail)
    render_app_loading_overlay(
        activity_slot,
        title="Please wait...",
        subtitle=text,
        detail=detail,
    )
    return payload


# Update the shared loading overlay.
def update_sidebar_activity(progress, value: float, text: str):
    if progress is not None:
        detail = f"{int(max(0.0, min(value, 1.0)) * 100)}%" if value > 0 else ""
        update_app_loading_state("Please wait...", text, detail)
        render_app_loading_overlay(
            progress["slot"],
            title="Please wait...",
            subtitle=text,
            detail=detail,
        )


# Mark the shared loading overlay as complete.
def finish_sidebar_activity(progress, text: str):
    if progress is not None:
        update_app_loading_state("Please wait...", text, "Done")
        render_app_loading_overlay(
            progress["slot"],
            title="Please wait...",
            subtitle=text,
            detail="Done",
        )


# Remove the shared loading overlay.
def clear_sidebar_activity(activity_slot):
    clear_app_loading_state()
    clear_app_loading_overlay(activity_slot)


def _record_background_connection_issue(error) -> None:
    # Background/external provider failures belong in the Bell, not a Toast.
    # Keep one Bell per outage; a later successful provider operation resets it.
    mark_provider_connection_issue(error)
    if st.session_state.get("provider_connection_notice_active"):
        return
    st.session_state.provider_connection_notice_active = True
    record_notification(
        title="Mailbox connection issue",
        message="MailMind could not synchronize with your email provider in the background.",
        kind="warning",
        workspace="inbox",
        details=[provider_error_message(error, action="refresh")],
        event_type="mailbox-background-sync-failed",
        entity_id="provider-connection",
    )


def _email_notification_details(store, folder: str, uids, *, limit: int = 5) -> tuple[list[str], str]:
    # Return specific subject/sender details for mailbox notifications.
    emails = []
    for uid in {str(value) for value in (uids or set()) if str(value)}:
        try:
            item = store.get_email(folder, uid) if store is not None else None
        except Exception:
            item = None
        if item:
            emails.append(item)

    emails.sort(key=lambda item: str(item.get("date") or item.get("date_display") or ""), reverse=True)
    details = []
    for item in emails[:limit]:
        subject = str(item.get("subject") or "(No Subject)").strip()
        sender = str(item.get("from") or "Unknown sender").strip()
        when = str(item.get("date_display") or "").strip()
        line = f"{subject} — From {sender}"
        if when:
            line += f" · {when}"
        details.append(line)
    if len(emails) > limit:
        details.append(f"+{len(emails) - limit} more email{'s' if len(emails) - limit != 1 else ''}")
    entity_id = str(emails[0].get("uid") or "") if len(emails) == 1 else ""
    return details, entity_id


class SecurityCatchupProgress:
    # Thread-safe progress snapshot for one small background catch-up batch.
    def __init__(self, total: int):
        self.total = max(0, int(total or 0))
        self.processed = 0
        self._lock = Lock()

    def advance(self) -> None:
        with self._lock:
            self.processed += 1

    def snapshot(self) -> tuple[int, int]:
        with self._lock:
            return self.processed, self.total


# Serialize Security LLM calls across low-priority catch-up and genuinely NEW
# mail. A running model request cannot be force-killed safely, but once it
# finishes the preemption token prevents catch-up from taking the model again;
# the waiting NEW-mail worker gets the next Security analysis slot.
_SECURITY_LLM_EXECUTION_LOCK = Lock()


class SecurityCatchupControl:
    # Cooperative preemption token for the low-priority old-mail worker. NEW
    # mailbox work may request a yield without killing a running Python thread.
    # The worker checks this token before expensive provider/model work and hands
    # any just-hydrated AI candidate back to the deferred queue if needed.
    def __init__(self):
        self._preempt = Event()

    def request_preempt(self) -> None:
        self._preempt.set()

    def should_preempt(self) -> bool:
        return self._preempt.is_set()


def _security_batch_for_items_with_resources(
    client, store, items: list[dict], folder: str, *, failures: list[dict] | None = None
) -> list[dict]:
    # Build Security batches only from a persisted full-message input. If an
    # incomplete email cannot be fetched right now, leave it pending instead of
    # finalizing/AI-refining a header-only fallback. Re-read the stored row after
    # hydration so CURRENT provider location always wins over stale raw evidence.
    if store is None:
        return []

    batch = []
    for item in items or []:
        uid = str(item.get("uid") or "").strip()
        if not uid:
            continue

        saved = store.get_email(folder, uid) or dict(item)
        cached_input_version = int(saved.get("security_input_version") or 0)
        is_full = bool(int(saved.get("is_full") or 0))

        if cached_input_version < 2 or not is_full:
            if client is None:
                continue
            full_result = get_full_email(
                client,
                uid,
                folder=folder,
                store=store,
                force_remote=True,
            )
            if not full_result.get("success"):
                # Keep security_input_version < 2 so catch-up/login can retry.
                if failures is not None:
                    failures.append({
                        "uid": uid,
                        "error": str(full_result.get("error") or ""),
                        "missing": bool(full_result.get("missing")),
                    })
                continue
            saved = store.get_email(folder, uid)
            if saved is None or int(saved.get("security_input_version") or 0) < 2:
                continue

        provider_spam = bool(int(saved.get("provider_spam") or 0))
        attachment_loader = getattr(store, "get_attachments", None)
        cached_attachments = (
            attachment_loader(folder, uid)
            if int(saved.get("is_full") or 0) and callable(attachment_loader)
            else []
        )
        email_data = normalize_security_input(
            saved,
            provider_spam=provider_spam,
            attachments=cached_attachments,
            full_message=True,
        )
        baseline = detect_spam(email_data)
        batch.append({"email": email_data, "baseline": baseline})
    return batch


def _security_batch_for_items(items: list[dict], folder: str) -> list[dict]:
    # UI-thread compatibility wrapper used by login/refresh/new-mail paths.
    return _security_batch_for_items_with_resources(
        st.session_state.get("imap_client"),
        st.session_state.get("email_store"),
        items,
        folder,
    )

def preclassify_pending_spam_security(
    folder: str = "INBOX", *, limit: int = 250, batch_size: int = 20
) -> int:
    # First-sync priority pass: finalize suspicious header-only candidates
    # before the workspace opens. Full/security_input_version=2 rows are durable
    # and are never returned to this generic login classifier.
    store = st.session_state.get("email_store")
    if store is None:
        return 0

    pending = store.get_pending_security_classifications(folder, limit=limit)

    # Match the older fast login behavior when there is nothing left to hydrate.
    # Do not arm a durable blocking gate, probe Ollama, or perform an extra
    # provider round-trip for an empty Security queue. If an earlier interrupted
    # run left a stale gate behind but all candidate rows are already complete,
    # the durable local state is sufficient to release the workspace safely.
    set_gate = getattr(store, "set_initial_security_gate_active", None)
    if not pending:
        st.session_state.initial_security_analysis_incomplete = False
        if callable(set_gate):
            set_gate(folder, active=False)
        return 0

    # This pass gates the first usable Inbox only while actual header-only
    # Security candidates remain. Keep that fact in SQLite so F5/WebSocket
    # replacement during provider hydration cannot expose incomplete mail.
    if callable(set_gate):
        set_gate(folder, active=True)

    # Full-message deterministic classification must not depend on Ollama. AI
    # refinement is optional, but every pending security candidate is first
    # hydrated from the provider and reclassified from the normalized full input.
    try:
        ai_ready = bool(get_ollama_status().get("model_ready"))
    except Exception:
        ai_ready = False

    completed = 0
    provider_work_succeeded = False
    size = max(1, int(batch_size or 20))
    for start in range(0, len(pending), size):
        chunk = pending[start:start + size]
        failures: list[dict] = []
        with security_trace_mode("login"):
            batch = _security_batch_for_items_with_resources(
                st.session_state.get("imap_client"),
                store,
                chunk,
                folder,
                failures=failures,
            )

        # A provider/network interruption during the blocking login Security pass
        # must never silently open a partially hydrated Inbox. Stop the gate, keep
        # the pending rows retryable, and hand control to the persistent Retry page.
        network_failure = next(
            (item for item in failures if is_network_error(item.get("error"))),
            None,
        )
        if network_failure is not None:
            error = str(network_failure.get("error") or "")
            mark_provider_connection_issue(error)
            st.session_state.initial_security_analysis_incomplete = True
            st.session_state.initial_sync_error = provider_error_message(
                error, action="login"
            )
            return completed

        if not batch:
            continue
        provider_work_succeeded = True

        # get_full_email() -> save_full() already persisted the deterministic
        # full-message verdict. When AI is unavailable, that verdict remains the
        # final baseline instead of leaving a header-only classification behind.
        if not ai_ready:
            completed += len(batch)
            continue

        try:
            with security_trace_mode("login"):
                results = classify_email_security_batch(batch)
        except RuntimeError as error:
            trace_security_detection(
                "AI_BATCH_ERROR", mode="login", payload={"error": str(error), "folder": folder}
            )
            print(f"[security] Automatic security classification skipped: {error}", flush=True)
            completed += len(batch)
            continue

        for item in chunk:
            uid = str(item.get("uid") or "")
            classification = results.get(uid)
            if not classification:
                continue
            if store.update_security_classification(folder, uid, classification):
                completed += 1

    # A normal first-login full sync already proved provider connectivity and
    # every required full-message fetch above reports network failures directly.
    # Only an interrupted durable-gate recovery performs the extra provider
    # confirmation before release. This preserves N9/N10 recovery semantics
    # without adding another network round-trip to every successful first login.
    if st.session_state.get("initial_security_recovery_check_required"):
        client = st.session_state.get("imap_client")
        provider_count = None
        if client is not None:
            try:
                provider_count = client.get_message_count(folder)
            except Exception:
                provider_count = None
        if provider_count is None:
            error = "Could not connect to your email provider during security analysis."
            mark_provider_connection_issue(error)
            st.session_state.initial_security_analysis_incomplete = True
            st.session_state.initial_sync_error = provider_error_message(
                error, action="login"
            )
            return completed

    st.session_state.initial_security_recovery_check_required = False
    mark_provider_connection_ok()
    st.session_state.initial_sync_error = ""
    st.session_state.initial_security_analysis_incomplete = False
    if callable(set_gate):
        set_gate(folder, active=False)
    return completed


_SECURITY_CATCHUP_UNSAFE_CATEGORIES = {
    "spam",
    "phishing",
    "malware",
    "scam / fraud",
    "impersonation",
    "suspicious",
}

# High-risk final Security verdicts are the one external/background exception
# that uses both an immediate Toast and a persistent Bell entry. Ordinary Spam
# stays lower urgency and uses Bell only.
_SECURITY_ALERT_CATEGORIES = {
    "phishing": "Phishing",
    "malware": "Malware",
    "scam / fraud": "Scam / Fraud",
    "impersonation": "Impersonation",
    "suspicious": "Suspicious",
}


def _run_security_catchup_batch(
    client,
    store,
    items: list[dict],
    folder: str,
    progress: SecurityCatchupProgress,
    ai_ready: bool,
    control: SecurityCatchupControl,
    deferred_ai_input=None,
) -> dict:
    # Process only a very small batch so mailbox catch-up stays low priority.
    # NEW mail may preempt this worker cooperatively. If preemption arrives after
    # an old message was already full-hydrated, preserve its pending AI refinement
    # in a deferred queue rather than silently treating deterministic Security as
    # the final catch-up result.
    deferred_input = {
        str(uid) for uid in (deferred_ai_input or set()) if str(uid)
    }
    hydrated = []
    completed_uids = []
    initial_is_spam = {}
    preempted = False

    for item in items or []:
        if control.should_preempt():
            preempted = True
            break
        uid = str(item.get("uid") or "").strip()
        if uid:
            initial_is_spam[uid] = int(item.get("is_spam") or 0)
        try:
            batch = _security_batch_for_items_with_resources(
                client, store, [item], folder
            )
            saved = store.get_email(folder, uid) if uid else None
            if (
                batch
                and saved is not None
                and int(saved.get("security_input_version") or 0) >= 2
            ):
                hydrated.extend(batch)
                completed_uids.append(uid)
        finally:
            progress.advance()

    ai_candidates = [
        entry
        for entry in hydrated
        if str((entry.get("baseline") or {}).get("category") or "")
        .strip()
        .casefold()
        in _SECURITY_CATCHUP_UNSAFE_CATEGORIES
    ]
    ai_candidate_uids = {
        str((entry.get("email") or {}).get("uid") or "").strip()
        for entry in ai_candidates
        if str((entry.get("email") or {}).get("uid") or "").strip()
    }

    deferred_ai_uids = set()
    deferred_ai_completed = set()
    if control.should_preempt():
        preempted = True
        # If the item became full while NEW mail arrived, remember only the
        # unsafe candidate that still deserves the old-mail contextual pass.
        deferred_ai_uids.update(ai_candidate_uids)
    elif ai_ready and ai_candidates:
        # Catch-up is explicitly lower priority than NEW mail. Wait for the
        # shared Security model slot in short intervals so a NEW-mail preemption
        # can stop this old-mail item before it starts an LLM request. Re-check
        # after acquiring the slot to close the race between Event check/acquire.
        acquired = False
        while not control.should_preempt():
            acquired = _SECURITY_LLM_EXECUTION_LOCK.acquire(timeout=SECURITY_LLM_LOCK_TIMEOUT_SECONDS)
            if acquired:
                break
        if not acquired or control.should_preempt():
            if acquired:
                _SECURITY_LLM_EXECUTION_LOCK.release()
            preempted = True
            deferred_ai_uids.update(ai_candidate_uids)
        else:
            try:
                try:
                    ai_results = classify_email_security_batch(ai_candidates)
                except RuntimeError as error:
                    print(f"[security-catchup] AI refinement skipped: {error}", flush=True)
                    ai_results = {}
            finally:
                _SECURITY_LLM_EXECUTION_LOCK.release()
            for uid, classification in ai_results.items():
                if classification:
                    store.update_security_classification(folder, uid, classification)
            deferred_ai_completed.update(deferred_input.intersection(ai_candidate_uids))
    elif deferred_input:
        # Model unavailable: deterministic full-message Security remains durable
        # and the old optional AI pass should not block completion forever.
        deferred_ai_completed.update(deferred_input)

    unsafe_uids = []
    unsafe_categories = {}
    routing_changed_uids = []
    for uid in completed_uids:
        saved = store.get_email(folder, uid)
        category = str((saved or {}).get("security_category") or "").strip().casefold()
        if category in _SECURITY_CATCHUP_UNSAFE_CATEGORIES:
            unsafe_uids.append(uid)
            unsafe_categories[category] = int(unsafe_categories.get(category, 0)) + 1
        if int((saved or {}).get("is_spam") or 0) != int(initial_is_spam.get(uid, 0)):
            routing_changed_uids.append(uid)

    return {
        "attempted": len(items or []),
        "completed_uids": completed_uids,
        "unsafe_uids": unsafe_uids,
        "unsafe_categories": unsafe_categories,
        "routing_changed_uids": routing_changed_uids,
        "preempted": preempted,
        "deferred_ai_uids": sorted(deferred_ai_uids),
        "deferred_ai_completed": sorted(deferred_ai_completed),
    }


def _security_catchup_deferred_ai_uids() -> set[str]:
    return {
        str(uid)
        for uid in st.session_state.get("security_catchup_deferred_ai_uids", set())
        if str(uid)
    }


def _new_mail_security_waiting_uids() -> set[str]:
    return {
        str(uid)
        for uid in st.session_state.get("new_mail_security_waiting_uids", set())
        if str(uid)
    }


def _durable_pending_new_mail_uids(folder: str) -> set[str]:
    store = st.session_state.get("email_store")
    getter = getattr(store, "get_pending_new_mail_uids", None)
    if not callable(getter):
        return set()
    try:
        return {str(uid) for uid in getter(folder) if str(uid)}
    except Exception as error:
        print(f"[mail-monitor] Could not load durable NEW-mail queue: {error}", flush=True)
        return set()


def _save_durable_pending_new_mail_uids(folder: str, uids) -> None:
    store = st.session_state.get("email_store")
    setter = getattr(store, "set_pending_new_mail_uids", None)
    if not callable(setter):
        return
    try:
        setter(folder, {str(uid) for uid in (uids or set()) if str(uid)})
    except Exception as error:
        print(f"[mail-monitor] Could not save durable NEW-mail queue: {error}", flush=True)


def _remember_durable_new_mail(folder: str, uids) -> set[str]:
    added = {str(uid) for uid in (uids or set()) if str(uid)}
    if not added:
        return _durable_pending_new_mail_uids(folder)
    pending = _durable_pending_new_mail_uids(folder)
    pending.update(added)
    _save_durable_pending_new_mail_uids(folder, pending)
    return pending


def _forget_durable_new_mail(folder: str, uids) -> set[str]:
    removed = {str(uid) for uid in (uids or set()) if str(uid)}
    pending = _durable_pending_new_mail_uids(folder)
    if removed:
        pending.difference_update(removed)
        _save_durable_pending_new_mail_uids(folder, pending)
    return pending


def _recover_hidden_new_mail_state(folder: str) -> tuple[set[str], set[str]]:
    # Streamlit Futures/session sets are intentionally transient. If the browser
    # WebSocket/session is replaced while NEW-mail Security is running, recover
    # the durable lifecycle queue and any orphaned hidden rows from SQLite.
    # Durable UIDs keep normal NEW/Unread/Auto Summary semantics. Orphaned rows
    # are still Security-checked and published, but do not replay a NEW event.
    store = st.session_state.get("email_store")
    if store is None:
        return set(), set()

    active = {str(uid) for uid in store.get_active_uids(folder) if str(uid)}
    durable_saved = _durable_pending_new_mail_uids(folder)
    durable = durable_saved.intersection(active)
    if durable != durable_saved:
        _save_durable_pending_new_mail_uids(folder, durable)

    session_pending = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }.intersection(active)
    recovered_durable = durable.difference(session_pending)
    session_pending.update(durable)
    st.session_state.pending_new_mail_notification_uids = session_pending
    if durable and not _new_mail_notification_cycles():
        _register_new_mail_notification_cycle(durable)

    # Rebuild Auto Summary staging only for UIDs we can prove were genuine NEW
    # from the durable queue. This preserves RESTORED != NEW and avoids replaying
    # uncertain orphan rows as fresh arrivals.
    if recovered_durable:
        _stage_auto_summary_arrivals(recovered_durable, set(), set())

    # A session may disappear after SQLite publication but before the in-memory
    # NEW lifecycle release (Unread/Bell/Auto hand-off). Finish that hand-off for
    # already-visible, Security-ready durable rows so they cannot loop forever in
    # the pending queue just because publish_security_ready() is now a no-op.
    already_published = set()
    for uid in durable:
        header = store.get_email(folder, uid)
        if (
            header is not None
            and bool(header.get("ui_visible"))
            and int(header.get("security_input_version") or 0) >= 2
        ):
            already_published.add(uid)
    if already_published:
        _release_published_new_mail(folder, already_published)
        session_pending = {
            str(uid)
            for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid)
        }

    hidden_getter = getattr(store, "get_hidden_security_uids", None)
    hidden = set()
    if callable(hidden_getter):
        try:
            hidden = {str(uid) for uid in hidden_getter(folder) if str(uid)}
        except Exception as error:
            print(f"[mail-monitor] Could not inspect hidden Security rows: {error}", flush=True)
    orphans = hidden.difference(session_pending)
    st.session_state.new_mail_security_recovery_uids = set(orphans)
    return session_pending, orphans


def _new_mail_security_priority_active() -> bool:
    # Anything already detected as NEW outranks old-mail catch-up, including the
    # short window before the contextual worker itself has been launched.
    return bool(
        _new_mail_security_refinement_active()
        or _new_mail_security_waiting_uids()
        or st.session_state.get("pending_mailbox_remote_count") is not None
        or {
            str(uid)
            for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid)
        }
        or {
            str(uid)
            for uid in st.session_state.get("new_mail_security_recovery_uids", set())
            if str(uid)
        }
    )


def _preempt_security_catchup_for_new_mail() -> None:
    # Cooperative only: Python cannot safely kill a thread that is inside a
    # provider/model request. The token makes the old-mail worker yield at its
    # next safe boundary and prevents another catch-up batch from starting.
    control = st.session_state.get("security_catchup_control")
    if control is not None:
        try:
            control.request_preempt()
        except Exception:
            pass
    future = st.session_state.get("security_catchup_future")
    if future is not None and not future.done():
        try:
            future.cancel()
        except Exception:
            pass


def _security_catchup_can_run() -> bool:
    return bool(
        st.session_state.get("logged_in")
        and st.session_state.get("inbox_loaded")
        and st.session_state.get("full_synced")
        and st.session_state.get("imap_client") is not None
        and st.session_state.get("email_store") is not None
        and not st.session_state.get("loading")
        and not st.session_state.get("app_loading_active")
        and not st.session_state.get("summary_processing")
        and not st.session_state.get("draft_processing")
        and not st.session_state.get("mailbox_sync_in_progress")
        and not _new_mail_security_refinement_active()
        and not _new_mail_security_priority_active()
    )


def _ensure_security_catchup_session(folder: str) -> int:
    store = st.session_state.get("email_store")
    if store is None:
        return 0
    remaining = (
        store.count_security_catchup_pending(folder)
        + len(_security_catchup_deferred_ai_uids())
    )
    initial = int(st.session_state.get("security_catchup_session_total", 0) or 0)
    if initial <= 0 and remaining > 0:
        st.session_state.security_catchup_session_total = remaining
        st.session_state.security_catchup_remaining = remaining
        st.session_state.security_catchup_completed_at = 0.0
        st.session_state.security_catchup_unsafe_count = 0
        st.session_state.security_catchup_category_counts = {}
        st.session_state.security_catchup_completion_notified = False
    elif initial > 0:
        st.session_state.security_catchup_remaining = remaining
    return remaining


def queue_security_catchup_background_toast(folder: str = "INBOX") -> bool:
    # The old-email Security review is intentionally background maintenance.
    # Do not reserve Inbox layout space or expose a live progress strip. Instead,
    # show one short native toast per Streamlit session so the user knows the
    # review is running without making it look like a blocking foreground job.
    if st.session_state.get("security_catchup_background_toast_shown"):
        return False
    if not st.session_state.get("logged_in") or not st.session_state.get("full_synced"):
        return False

    store = st.session_state.get("email_store")
    if store is None:
        return False
    # F5/browser session replacement creates a fresh Streamlit session. Keep the
    # "Security check running" notice durable in the account DB for the lifetime
    # of this catch-up cycle so it appears once, not once per browser refresh.
    if store.security_catchup_notice_active(folder):
        st.session_state.security_catchup_background_toast_shown = True
        return False
    try:
        remaining = (
            store.count_security_catchup_pending(folder)
            + len(_security_catchup_deferred_ai_uids())
        )
    except Exception:
        return False
    if remaining <= 0:
        return False

    store.set_security_catchup_notice_active(folder, active=True)
    st.session_state.security_catchup_background_toast_shown = True
    push_inbox_toast(
        "MailMind is reviewing older emails in the background. You can keep using the app.",
        "waiting",
        title="Security check running",
        event_type="security-catchup-running",
        notify_bell=False,
    )
    return True


def start_security_catchup_if_needed(folder: str = "INBOX") -> bool:
    # Start one low-priority batch. The next batch is launched by the timed
    # monitor only after this future completes and a short cooldown passes.
    if not _security_catchup_can_run():
        return False
    future = st.session_state.get("security_catchup_future")
    if future is not None and not future.done():
        return False
    if time.time() < float(st.session_state.get("security_catchup_next_at", 0.0) or 0.0):
        return False

    store = st.session_state.email_store
    remaining = _ensure_security_catchup_session(folder)
    if remaining <= 0:
        return False

    deferred_ai = _security_catchup_deferred_ai_uids()
    deferred_batch = set()
    items = []
    if deferred_ai:
        for uid in sorted(deferred_ai)[:SECURITY_CATCHUP_BATCH_SIZE]:
            item = store.get_email(folder, uid)
            if item is not None:
                items.append(item)
                deferred_batch.add(uid)
    if not items:
        items = store.get_security_catchup_candidates(
            folder, limit=SECURITY_CATCHUP_BATCH_SIZE
        )
    if not items:
        return False

    try:
        ai_ready = bool(get_ollama_status().get("model_ready"))
    except Exception:
        ai_ready = False

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="security-catchup")
    progress = SecurityCatchupProgress(len(items))
    control = SecurityCatchupControl()
    st.session_state.security_catchup_executor = executor
    st.session_state.security_catchup_progress = progress
    st.session_state.security_catchup_control = control
    st.session_state.security_catchup_batch_size = len(items)
    st.session_state.security_catchup_future = executor.submit(
        _run_security_catchup_batch,
        st.session_state.imap_client,
        store,
        items,
        folder,
        progress,
        ai_ready,
        control,
        deferred_batch,
    )
    return True


def _finish_security_catchup_batch(folder: str) -> tuple[bool, bool]:
    # Return (finished_batch, inbox_routing_changed).
    future = st.session_state.get("security_catchup_future")
    if future is None or not future.done():
        return False, False

    routing_changed = False
    try:
        result = future.result()
    except Exception as error:
        print(f"[security-catchup] Batch failed: {error}", flush=True)
        result = {
            "completed_uids": [], "unsafe_uids": [], "unsafe_categories": {},
            "routing_changed_uids": [], "preempted": False,
            "deferred_ai_uids": [], "deferred_ai_completed": [],
        }
    finally:
        executor = st.session_state.pop("security_catchup_executor", None)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        st.session_state.pop("security_catchup_future", None)
        st.session_state.pop("security_catchup_progress", None)
        st.session_state.pop("security_catchup_control", None)
        completed_count = len(result.get("completed_uids", []) or []) if "result" in locals() else 0
        if bool(result.get("preempted")):
            retry_delay = 0.5
        else:
            retry_delay = (
                SECURITY_CATCHUP_COOLDOWN_SECONDS if completed_count > 0 else 20.0
            )
        st.session_state.security_catchup_next_at = time.time() + retry_delay

    deferred_ai = _security_catchup_deferred_ai_uids()
    deferred_ai.update(
        str(uid) for uid in result.get("deferred_ai_uids", []) if str(uid)
    )
    deferred_ai.difference_update(
        str(uid) for uid in result.get("deferred_ai_completed", []) if str(uid)
    )
    st.session_state.security_catchup_deferred_ai_uids = deferred_ai

    unsafe_uids = {
        str(uid) for uid in result.get("unsafe_uids", []) if str(uid)
    }
    store = st.session_state.get("email_store")
    completed_uids = {
        str(uid) for uid in result.get("completed_uids", []) if str(uid)
    }
    newly_published = (
        store.publish_security_ready(folder, completed_uids)
        if store is not None else set()
    )
    if newly_published:
        _release_published_new_mail(folder, newly_published)

    if unsafe_uids:
        st.session_state.security_catchup_unsafe_count = int(
            st.session_state.get("security_catchup_unsafe_count", 0) or 0
        ) + len(unsafe_uids)
        category_counts = dict(st.session_state.get("security_catchup_category_counts", {}) or {})
        for category, count in dict(result.get("unsafe_categories", {}) or {}).items():
            clean_category = str(category or "").strip().casefold()
            if clean_category:
                category_counts[clean_category] = int(category_counts.get(clean_category, 0)) + int(count or 0)
        st.session_state.security_catchup_category_counts = category_counts
        # UI-only review state: catch-up findings appear under Spam -> Newly
        # detected until the user opens them. This does not change Security
        # classification, provider location, or email read/unread state.
        if store is not None:
            store.mark_security_unreviewed(folder, unsafe_uids)
    routing_changed = bool(
        {str(uid) for uid in result.get("routing_changed_uids", []) if str(uid)}
    ) or bool(newly_published)
    # Refresh the app when a newly detected finding is added so the Spam
    # sub-item count/filter updates immediately even if routing was already Spam.
    routing_changed = routing_changed or bool(unsafe_uids)

    remaining = (
        store.count_security_catchup_pending(folder)
        + len(_security_catchup_deferred_ai_uids())
        if store is not None else 0
    )
    st.session_state.security_catchup_remaining = remaining
    if remaining <= 0:
        st.session_state.security_catchup_completed_at = time.time()
        st.session_state.security_catchup_next_at = 0.0
        if store is not None:
            store.set_security_catchup_notice_active(folder, active=False)
        unsafe_count = int(st.session_state.get("security_catchup_unsafe_count", 0) or 0)
        if unsafe_count > 0 and not bool(st.session_state.get("security_catchup_completion_notified", False)):
            st.session_state.security_catchup_completion_notified = True
            category_counts = dict(st.session_state.get("security_catchup_category_counts", {}) or {})

            # Notification contract:
            #   user-triggered -> Toast
            #   background/external -> Bell
            #   critical Security -> one grouped Toast + Bell
            # Catch-up is background work, but any high-risk verdict is the explicit
            # critical-security exception.  Keep ordinary Spam Bell-only.
            critical_details = []
            critical_count = 0
            for category, count in sorted(category_counts.items()):
                clean_category = str(category or "").strip().casefold()
                if clean_category not in _SECURITY_ALERT_CATEGORIES:
                    continue
                amount = int(count or 0)
                if amount <= 0:
                    continue
                critical_count += amount
                critical_details.append(
                    f"{_SECURITY_ALERT_CATEGORIES[clean_category]}: {amount}"
                )

            spam_count = int(category_counts.get("spam", 0) or 0)
            if critical_count > 0:
                noun = "email" if critical_count == 1 else "emails"
                push_inbox_toast(
                    f"MailMind detected {critical_count} potentially harmful {noun} during Security catch-up.",
                    "security",
                    title="Security alert",
                    details=critical_details,
                    event_type="security-catchup-critical",
                    notify_bell=True,
                )

            if spam_count > 0:
                noun = "email" if spam_count == 1 else "emails"
                record_notification(
                    title="Spam detected during Security check",
                    message=f"MailMind detected {spam_count} spam {noun} during Security catch-up.",
                    kind="info",
                    workspace="spam",
                    details=[f"Spam: {spam_count}"],
                    event_type="security-catchup-spam",
                )
    return True, routing_changed


@st.fragment(run_every=SECURITY_CATCHUP_FRAGMENT_SECONDS)
def monitor_security_catchup(folder: str = "INBOX") -> None:
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return
    # Poll/start the low-priority catch-up only on the fragment timer. A fragment
    # also executes inline during every full-app rerun. Gate that inline call
    # *before* consuming a completed worker future: finishing the batch first can
    # request another full-app rerun while the current root run is still mounting
    # and intermittently leave the browser on a blank frame.
    if not st.session_state.get("logged_in"):
        return
    # Low-priority catch-up must yield to any blocking foreground operation.
    # This prevents a completed catch-up batch from requesting a full-app rerun
    # while Summary/Draft/loading overlays are actively being painted.
    if (
        st.session_state.get("app_loading_active")
        or st.session_state.get("summary_processing")
        or st.session_state.get("draft_processing")
    ):
        return

    generation = int(st.session_state.get("app_run_generation", 0) or 0)
    seen_generation = int(
        st.session_state.get("security_catchup_monitor_seen_generation", -1) or -1
    )
    if seen_generation != generation:
        st.session_state.security_catchup_monitor_seen_generation = generation
        return

    finished, routing_changed = _finish_security_catchup_batch(folder)
    if routing_changed:
        st.session_state.inbox_loaded_view_signature = None
        st.rerun(scope="app")
        return

    # If a mailbox change was already detected, give its Security-first sync
    # priority and wait for the next timer cycle before doing old-mail catch-up.
    if st.session_state.get("pending_mailbox_remote_count") is not None:
        return

    start_security_catchup_if_needed(folder)


def security_catchup_status(folder: str = "INBOX") -> dict:
    # UI-readable snapshot. The database remains the durable source of truth.
    store = st.session_state.get("email_store")
    if store is None or not st.session_state.get("full_synced"):
        return {"active": False, "complete": False}

    remaining = _ensure_security_catchup_session(folder)
    total = int(st.session_state.get("security_catchup_session_total", 0) or 0)
    # Each save_full() commits security_input_version=2 immediately, so the
    # SQLite remaining count already includes in-flight batch progress. Do not
    # add the worker counter again or the UI would double-count completed mail.
    completed = max(0, total - remaining) if total > 0 else 0

    completed_at = float(st.session_state.get("security_catchup_completed_at", 0.0) or 0.0)
    show_complete = bool(completed_at and (time.time() - completed_at) <= 6.0)
    unsafe_count = int(st.session_state.get("security_catchup_unsafe_count", 0) or 0)
    return {
        "active": bool(remaining > 0 or st.session_state.get("security_catchup_future")),
        "complete": show_complete,
        "total": total,
        "completed": completed,
        "remaining": remaining,
        "unsafe_count": unsafe_count,
        "paused_for_new_mail": bool(_new_mail_security_priority_active()),
    }


def sync_checked_uids_from_widgets() -> set[str]:
    """Consume the current Inbox checkbox values exactly once per user change.

    The sidebar (and Generate Summary) renders before the Inbox body.  Checkbox
    widgets therefore cannot rely on a render-time reconciliation step: doing so
    makes the count/button one rerun behind, while callbacks create synthetic
    events when Streamlit unmounts the Inbox.

    The last rendered Inbox page publishes its visible UIDs and page-checkbox
    key.  On the next normal rerun we read only those mounted row widgets, apply
    a real Select-all value change once, then immediately normalize the page
    checkbox from the resulting UID set.  Background reruns with unchanged
    widget values are therefore no-ops.
    """
    selected_uids = {
        str(uid) for uid in st.session_state.get("checked_uids", set())
        if str(uid)
    }
    visible_uids = tuple(
        str(uid) for uid in st.session_state.get("inbox_selection_visible_uids", ())
        if str(uid)
    )
    page_key = str(st.session_state.get("inbox_selection_page_key") or "")

    # First consume individual row changes from the currently mounted page only.
    # Hidden/stale checkbox keys from old pages can never re-add a selection.
    row_changed = False
    for uid in visible_uids:
        key = f"chk_{uid}"
        if key not in st.session_state:
            continue
        checked = bool(st.session_state.get(key, False))
        was_checked = uid in selected_uids
        if checked == was_checked:
            continue
        row_changed = True
        trace_action("inbox-select-one", checked=checked)
        if checked:
            selected_uids.add(uid)
        else:
            selected_uids.discard(uid)

    # Select-all is callback-free.  The previous render records the value it
    # intentionally painted; only a difference from that processed value is a
    # new user action.  This avoids treating a background remount as Select-all.
    processed_key = str(
        st.session_state.get("inbox_selection_processed_page_key") or ""
    )
    processed_value = bool(
        st.session_state.get("inbox_selection_processed_page_value", False)
    )
    page_changed = False
    if page_key and page_key in st.session_state and processed_key == page_key:
        current_page_value = bool(st.session_state.get(page_key, False))
        page_changed = current_page_value != processed_value
        if page_changed:
            trace_action(
                "inbox-select-page",
                selected=current_page_value,
                visible_count=len(visible_uids),
            )
            if current_page_value:
                selected_uids.update(visible_uids)
            else:
                selected_uids.difference_update(visible_uids)

    # Normalize visible row widgets and Select-all from the authoritative set so
    # mode changes/background reruns cannot leave the visual state out of sync.
    all_selected = bool(visible_uids) and all(uid in selected_uids for uid in visible_uids)
    for uid in visible_uids:
        st.session_state[f"chk_{uid}"] = uid in selected_uids
    if page_key:
        st.session_state[page_key] = all_selected
        st.session_state.inbox_selection_processed_page_key = page_key
        st.session_state.inbox_selection_processed_page_value = all_selected

    if row_changed or page_changed:
        arm_foreground_interaction()

    st.session_state.checked_uids = selected_uids
    return selected_uids


def has_checked_emails() -> bool:
    # Return whether at least one email is currently checked.
    return bool(sync_checked_uids_from_widgets())


# Apply one saved database page to the current inbox state.
def _apply_cached_page(page: dict, offset: int):
    st.session_state.emails = page["emails"]
    st.session_state.inbox_total = page["total"]
    # Only an unfiltered Inbox page is allowed to replace the full Inbox total.
    # This prevents the Unread subfilter count from leaking into the main badge.
    if str(st.session_state.get("inbox_filter") or "all").casefold() == "all":
        st.session_state.inbox_all_total = int(page.get("total", 0) or 0)
    st.session_state.inbox_has_more = page.get("has_more", False)
    st.session_state.inbox_offset = offset


# Apply one saved database page to the current search state.
def _apply_cached_search_page(page: dict, offset: int):
    st.session_state.search_results = page["emails"]
    st.session_state.search_total = page["total"]
    st.session_state.inbox_search_offset = offset


# Build the signature for the complete Inbox view. Search, filters, arranging,
# sorting, and unread membership all participate so a changed choice always
# reloads from SQLite before the ten-row page is rendered.
def inbox_view_signature(search_mode: bool = False, query: str = "") -> tuple:
    filter_key = str(st.session_state.get("inbox_filter") or "all").casefold()
    arrange_by = str(st.session_state.get("inbox_arrange_by") or "date").casefold()
    sort_order = str(st.session_state.get("inbox_sort_order") or "newest").casefold()
    spam_category = (
        str(st.session_state.get("spam_category_filter") or "all").strip()
        if filter_key == "spam"
        else "all"
    )
    spam_detected_only = (
        bool(st.session_state.get("spam_detected_only", False))
        if filter_key == "spam"
        else False
    )
    unread_uids = tuple(sorted(
        str(uid) for uid in st.session_state.get("new_email_uids", set())
    ))
    return (
        bool(search_mode),
        str(query or "").strip(),
        filter_key,
        arrange_by,
        sort_order,
        spam_category,
        spam_detected_only,
        unread_uids,
    )


# Load one already-filtered/sorted inbox page from SQLite. LIMIT/OFFSET are
# applied only after the complete saved inbox has been searched and filtered.
def load_local_page(
    offset: int = 0,
    folder: str = "INBOX",
    *,
    search_mode: bool = False,
    query: str = "",
) -> bool:
    signature = inbox_view_signature(search_mode=search_mode, query=query)
    (
        _, normalized_query, filter_key, arrange_by, sort_order,
        spam_category, spam_detected_only, unread_tuple,
    ) = signature
    unread_uids = set(unread_tuple)
    result = load_cached_inbox(
        st.session_state.email_store,
        limit=MAX_EMAILS_FETCH,
        offset=offset,
        folder=folder,
        filter_key=filter_key,
        arrange_by=arrange_by,
        sort_order=sort_order,
        unread_uids=unread_uids,
        query=normalized_query,
        security_category=spam_category,
        security_detected_only=spam_detected_only,
    )
    if not result["success"]:
        st.error(f"Could not load the local inbox: {result['error']}")
        return False

    if search_mode:
        _apply_cached_search_page(result, offset)
    else:
        _apply_cached_page(result, offset)
    st.session_state.inbox_loaded_view_signature = signature
    return True


# Open the saved inbox or fetch the first page when it is empty.
def load_inbox_if_needed(activity_slot, folder: str = "INBOX"):
    if st.session_state.inbox_loaded:
        return

    inbox_progress = start_sidebar_activity(
        activity_slot, "Opening saved inbox...", 0.08
    )
    inbox_load_succeeded = True
    cached = load_cached_inbox(
        st.session_state.email_store,
        limit=MAX_EMAILS_FETCH,
        offset=0,
        folder=folder,
    )
    if not cached["success"]:
        clear_sidebar_activity(activity_slot)
        st.error(f"Could not open the local inbox: {cached['error']}")
        st.stop()

    sync_state = st.session_state.email_store.get_sync_state(folder)

    if cached["total"] > 0:
        # Returning users should see the saved first page immediately. Do not
        # wait for a network message-count request during login/refresh.
        update_sidebar_activity(
            inbox_progress, 0.78, "Preparing saved inbox..."
        )
        _apply_cached_page(cached, 0)

        if sync_state and sync_state.get("full_sync_complete"):
            st.session_state.full_synced = True
        elif sync_state is None:
            # Older databases already containing mail are valid local caches.
            # Mark them complete without a remote round-trip; the normal
            # new-mail checker will verify the server shortly afterward.
            st.session_state.email_store.mark_sync_complete(
                folder, cached["total"], cached["total"]
            )
            st.session_state.full_synced = True

        # Skip the immediate remote count check on this same run. It will run
        # on a later rerun after the short mailbox poll interval instead of delaying UI.
        st.session_state.last_mail_check = time.time()
        st.session_state.last_mail_reconcile = time.time()
    else:
        if st.session_state.get("post_login_loading"):
            # The workspace is intentionally gated during first-time login, so
            # do not fetch the first remote page and then fetch it again as part
            # of the full sync. The full Inbox + Spam/Junk sync below will save
            # everything once, then load the local first page.
            update_sidebar_activity(
                inbox_progress, 0.42, "Preparing first-time mailbox sync..."
            )
        else:
            update_sidebar_activity(
                inbox_progress, 0.42, "Fetching the first inbox page..."
            )
            first_page = refresh_inbox(
                st.session_state.imap_client,
                limit=MAX_EMAILS_FETCH,
                offset=0,
                refresh=True,
                store=st.session_state.email_store,
                folder=folder,
                sync_source="initial_page",
            )
            if first_page["success"]:
                update_sidebar_activity(
                    inbox_progress, 0.86, "Loading the saved inbox page..."
                )
                load_local_page(0, folder)
                st.session_state.last_mail_check = time.time()
                st.session_state.last_mail_reconcile = time.time()
            else:
                inbox_load_succeeded = False
                st.error(f"Could not fetch inbox: {first_page['error']}")

    st.session_state.inbox_loaded = True
    if inbox_load_succeeded:
        finish_sidebar_activity(inbox_progress, "Inbox ready")
    clear_sidebar_activity(activity_slot)


# Run the full mailbox sync only when it has never completed.
def run_full_sync_if_needed(activity_slot, folder: str = "INBOX"):
    if not (
        st.session_state.inbox_loaded
        and not st.session_state.full_synced
        and not st.session_state.full_sync_attempted
    ):
        return

    st.session_state.full_sync_attempted = True
    before_uids = st.session_state.email_store.get_active_uids(folder)
    unavailable_uids_before = st.session_state.email_store.get_unavailable_uids(folder)
    sync_progress = start_sidebar_activity(
        activity_slot, "Syncing Inbox, Spam, and Junk emails...", 0.0
    )

    # Update the first-time sync progress after each saved batch.
    def _update_sync_progress(synced, total):
        fraction = min(synced / total, 1.0) if total else 0.0
        update_sidebar_activity(
            sync_progress,
            fraction,
            f"First-time sync: {synced:,} / {total or '?'}",
        )

    try:
        sync_result = sync_all_inbox(
            st.session_state.imap_client,
            st.session_state.email_store,
            folder=folder,
            page_size=MAILBOX_SYNC_PAGE_SIZE,
            progress_callback=_update_sync_progress,
        )
    except Exception as error:
        sync_result = {
            "success": False,
            "error": str(error),
            "synced": 0,
            "total": 0,
            "missing_uids": [],
        }

    if sync_result["success"]:
        mark_provider_connection_ok()
        st.session_state.initial_sync_error = ""
        apply_confirmed_deletions(sync_result.get("missing_uids", []))
        after_uids = st.session_state.email_store.get_active_uids(folder)
        restored_uids, _genuine_new = _classify_arrivals(
            folder, after_uids.difference(before_uids), unavailable_uids_before
        )
        _notify_restored_emails(
            st.session_state.email_store, folder, restored_uids
        )
        finish_sidebar_activity(sync_progress, "First-time sync complete")
        st.session_state.full_synced = True
        st.session_state.last_mail_check = time.time()
        st.session_state.last_mail_reconcile = time.time()
        load_local_page(0, folder)
    else:
        error = sync_result.get("error") or "Unknown synchronization error"
        mark_provider_connection_issue(error)
        st.session_state.initial_sync_error = provider_error_message(error, action="login")
        print(
            f"[app] Full sync stopped after {sync_result['synced']} email(s): "
            f"{error}",
            flush=True,
        )
    clear_sidebar_activity(activity_slot)


# The fragment wakes frequently, but the provider is contacted only once per
# poll interval. User clicks never count as polling opportunities.


def _summary_identity_records(folder: str) -> list[dict]:
    # Return saved individual/batch source records used to recognize a restored
    # provider message even when its provider UID changed during the restore.
    summary_store = st.session_state.get("summary_store")
    if summary_store is None:
        return []

    records = list(summary_store.get_duplicate_records(folder))
    known = {str(item.get("uid") or "").strip() for item in records}
    for item in st.session_state.get("summaries", []):
        uid = str(item.get("uid") or "").strip()
        if uid and uid not in known:
            records.append(dict(item))
            known.add(uid)
    return records


def _classify_arrivals(
    folder: str,
    candidate_uids,
    unavailable_uids_before,
) -> tuple[set[str], set[str]]:
    # Classify mailbox arrivals before they reach new-mail notifications or the
    # Auto Summary queue. RESTORED messages are never treated as NEW.
    store = st.session_state.email_store
    candidates = {str(uid) for uid in (candidate_uids or set()) if str(uid)}
    headers = []
    for uid in candidates:
        item = store.get_email(folder, uid)
        if item is not None:
            headers.append(item)

    identity_records = _summary_identity_records(folder)
    known_identity_uids = {
        str(item.get("uid") or "").strip()
        for item in identity_records
        if str(item.get("uid") or "").strip()
    }
    # Restoration must not depend on whether the old email happened to have a
    # summary. Include unavailable cached email identities as well, so providers
    # that assign a new UID on restore can still reuse the original Security state.
    for old_uid in {str(uid) for uid in (unavailable_uids_before or set()) if str(uid)}:
        if old_uid in known_identity_uids:
            continue
        previous = store.get_email(folder, old_uid, include_unavailable=True)
        if previous is not None:
            identity_records.append(previous)
            known_identity_uids.add(old_uid)

    restored, genuine_new, relinks = classify_restored_arrivals(
        headers,
        unavailable_uids_before,
        identity_records,
    )

    # A candidate should normally have a cached header. If one is temporarily
    # missing, keep the old NEW behavior rather than silently dropping it.
    classified = restored.union(genuine_new)
    genuine_new.update(candidates.difference(classified))

    if relinks:
        _relink_summary_uids(folder, relinks)

    if restored:
        restored_state = {
            str(uid) for uid in st.session_state.get("restored_email_uids", set())
            if str(uid)
        }
        restored_state.update(restored)
        st.session_state.restored_email_uids = restored_state

        # Defensive cleanup for races/older session state: RESTORED is a
        # lifecycle-only event, never a NEW-mail or Auto Summary arrival.
        st.session_state.new_email_uids = {
            str(uid) for uid in st.session_state.get("new_email_uids", set())
            if str(uid) and str(uid) not in restored
        }
        st.session_state.pending_new_mail_notification_uids = {
            str(uid)
            for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid) and str(uid) not in restored
        }
        _forget_durable_new_mail(folder, restored)
        _drop_auto_summary_uids(restored)

    return restored, genuine_new


def _security_catchup_notification_window_active() -> bool:
    # Suppress provider move/restore Bell entries only while the signed-in
    # workspace is still inside the *blocking* first-login/recovery gate.
    #
    # Do NOT use app_loading_active here: Manual Refresh intentionally owns the
    # shared loading overlay while it reconciles provider folders. External
    # Inbox <-> Spam/Junk transitions discovered by that refresh are still real
    # background/provider lifecycle events and must create their Bell entry.
    return bool(
        st.session_state.get("post_login_loading")
        or st.session_state.get("initial_security_analysis_incomplete")
    )


def _provider_location_counts_from_signature(signature) -> dict[str, int] | None:
    # Normalize provider-specific folder-count signatures into the two MailMind
    # received-mail locations. Graph reports (inbox, junk); IMAP providers may
    # use Spam/Junk/Bulk display names. Any non-Inbox entry in this restricted
    # signature is a Spam/Junk source because clients expose only those folders.
    rows = list(signature or ())
    if not rows:
        return None
    inbox_count = 0
    spam_count = 0
    parsed = False
    for item in rows:
        try:
            name, count = item
            count = int(count or 0)
        except (TypeError, ValueError):
            continue
        parsed = True
        normalized = str(name or "").strip().casefold()
        if normalized == "inbox":
            inbox_count += count
        else:
            spam_count += count
    if not parsed:
        return None
    return {"inbox": inbox_count, "spam": spam_count}


def _provider_location_counts_changed(store, folder: str, signature) -> bool:
    # Compare the provider's cheap folder counts with the cache's persisted
    # provider_spam flags. This catches a move on the very first poll after
    # login instead of requiring a previous in-memory signature or waiting for
    # the slower five-minute full reconciliation.
    current = _provider_location_counts_from_signature(signature)
    local_reader = getattr(store, "get_provider_location_counts", None)
    if current is None or not callable(local_reader):
        return False
    try:
        local = dict(local_reader(folder) or {})
    except Exception:
        return False
    return current != {
        "inbox": int(local.get("inbox") or 0),
        "spam": int(local.get("spam") or 0),
    }


def _mailbox_remote_count_baseline(store, folder: str, local_count: int) -> int:
    """Return the last provider total successfully accepted by MailMind.

    The raw number of active SQLite rows is not a safe polling baseline. Old or
    partially reconciled caches can legitimately differ from the provider total;
    comparing every timer tick to that raw row count creates an endless full-app
    rerun loop even when the provider mailbox has not changed. The persisted
    sync-state remote_total is the provider-to-provider comparison we actually
    need. Fake/legacy stores without sync state keep the old local-count fallback.
    """
    reader = getattr(store, "get_sync_state", None)
    if callable(reader):
        try:
            state = reader(folder) or {}
            remote_total = state.get("remote_total")
            if remote_total is not None:
                return int(remote_total)
        except (TypeError, ValueError, AttributeError, KeyError):
            pass
        except Exception:
            # Polling stability must not fail merely because an optional sync-state
            # reader is unavailable; retain the historical local-count fallback.
            pass
    return int(local_count or 0)


def _notify_restored_emails(store, folder: str, restored_uids) -> None:
    # RESTORED is lifecycle-only and lower urgency: persist it in the Bell, but
    # do not interrupt the user with a toast and never promote it to NEW mail.
    restored = {str(uid) for uid in (restored_uids or set()) if str(uid)}
    if not restored or _security_catchup_notification_window_active():
        return
    count = len(restored)
    noun = "email" if count == 1 else "emails"
    details, entity_id = _email_notification_details(store, folder, restored)
    record_notification(
        title="Email restored" if count == 1 else "Emails restored",
        message=f"{count} {noun} restored to the mailbox.",
        kind="info",
        workspace="inbox",
        details=details,
        event_type="email-restored",
        entity_id=entity_id,
    )


def _notify_provider_location_moves(store, folder: str, moved_to_inbox_uids, moved_to_spam_uids) -> None:
    # Provider-side Inbox <-> Spam/Junk movement is a persistent background
    # event, not a MailMind foreground action. Bell only; no toast. Suppress it
    # only while the first-login/recovery workspace gate is still blocking.
    if store is None or _security_catchup_notification_window_active():
        return

    moved_in = {str(uid) for uid in (moved_to_inbox_uids or set()) if str(uid)}
    moved_spam = {str(uid) for uid in (moved_to_spam_uids or set()) if str(uid)}

    if moved_spam:
        count = len(moved_spam)
        noun = "email" if count == 1 else "emails"
        details, entity_id = _email_notification_details(store, folder, moved_spam)
        record_notification(
            title="Email moved to Spam" if count == 1 else "Emails moved to Spam",
            message=f"{count} {noun} moved from Inbox to Spam/Junk in your email provider.",
            kind="info",
            workspace="spam",
            details=details,
            event_type="email-moved-to-spam",
            entity_id=entity_id,
        )

    if moved_in:
        count = len(moved_in)
        noun = "email" if count == 1 else "emails"
        details, entity_id = _email_notification_details(store, folder, moved_in)
        record_notification(
            title="Email restored to Inbox" if count == 1 else "Emails restored to Inbox",
            message=f"{count} {noun} restored from Spam/Junk to Inbox in your email provider.",
            kind="info",
            workspace="inbox",
            details=details,
            event_type="email-restored-to-inbox",
            entity_id=entity_id,
        )


def _new_mail_notification_cycles() -> list[dict]:
    # Keep notification grouping tied to the mailbox detection cycle even though
    # Security publication now happens one email at a time. Each cycle tracks
    # the genuine NEW UIDs discovered together and which of those have already
    # reached their final Security-routed UI state.
    cycles = []
    for raw in list(st.session_state.get("new_mail_notification_cycles", []) or []):
        if not isinstance(raw, dict):
            continue
        uids = {str(uid) for uid in raw.get("uids", set()) if str(uid)}
        if not uids:
            continue
        ready = {
            str(uid) for uid in raw.get("ready", set())
            if str(uid) and str(uid) in uids
        }
        cycles.append({"uids": uids, "ready": ready})
    return cycles


def _register_new_mail_notification_cycle(uids) -> None:
    # One fetch/reconciliation pass is one notification detection cycle. Later
    # arrivals stay in a separate cycle even if an earlier Security worker is
    # still running, preserving NT-032/033/034 grouping semantics.
    incoming = {str(uid) for uid in (uids or set()) if str(uid)}
    if not incoming:
        return
    cycles = _new_mail_notification_cycles()
    tracked = set().union(*(cycle["uids"] for cycle in cycles)) if cycles else set()
    incoming.difference_update(tracked)
    if incoming:
        cycles.append({"uids": set(incoming), "ready": set()})
    st.session_state.new_mail_notification_cycles = cycles


def _mark_new_mail_notification_ready(uids) -> None:
    ready_now = {str(uid) for uid in (uids or set()) if str(uid)}
    if not ready_now:
        return
    cycles = _new_mail_notification_cycles()
    tracked = set()
    for cycle in cycles:
        overlap = cycle["uids"].intersection(ready_now)
        if overlap:
            cycle["ready"].update(overlap)
            tracked.update(overlap)
    # Recovery from a replaced Streamlit session may lose the transient cycle
    # registry while the durable NEW queue survives. Preserve notification
    # delivery by treating those recovered UIDs as one fallback cycle.
    untracked = ready_now.difference(tracked)
    if untracked:
        cycles.append({"uids": set(untracked), "ready": set(untracked)})
    st.session_state.new_mail_notification_cycles = cycles


def _flush_completed_new_mail_notification_cycles(store, folder: str) -> None:
    cycles = _new_mail_notification_cycles()
    if not cycles:
        return
    pending = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }
    remaining = []
    for cycle in cycles:
        # A cycle is notification-ready only when none of its UIDs are still
        # waiting for Security publication. UI publication itself remains
        # per-email; only the Bell/critical Toast stays grouped per detection
        # cycle as required by the notification contract.
        if cycle["uids"].intersection(pending):
            remaining.append(cycle)
            continue
        if cycle["ready"]:
            _notify_new_emails_after_security(store, folder, cycle["ready"])
    st.session_state.new_mail_notification_cycles = remaining


def _notify_new_emails_after_security(store, folder: str, new_uids) -> None:
    # Notification routing only: Security classification/routing itself is locked.
    # Wait for the final verdict so unsafe mail never produces a misleading generic
    # "New email" Bell entry before becoming a Security finding.
    candidates = {str(uid) for uid in (new_uids or set()) if str(uid)}
    if not candidates or store is None:
        return

    normal_uids = set()
    spam_uids = set()
    high_risk_by_category = {}
    for uid in candidates:
        item = store.get_email(folder, uid)
        if item is None:
            continue
        category = str(item.get("security_category") or "").strip().casefold()
        if category in _SECURITY_ALERT_CATEGORIES:
            high_risk_by_category.setdefault(category, set()).add(uid)
            continue
        # Ordinary MailMind Spam is lower urgency than Phishing/Malware/Suspicious:
        # keep it out of toast UI, but persist one Bell notification after the final
        # Security verdict. Promotional/provider-Spam cases are intentionally not
        # treated as ordinary Spam notifications.
        if category == "spam":
            spam_uids.add(uid)
            continue
        # Other provider-routed Security items use Spam/Detected state only.
        # Safe/Misclassified/Promotional messages that remain in Inbox follow the
        # normal new-mail notification path.
        if bool(item.get("is_spam")):
            continue
        normal_uids.add(uid)

    if normal_uids:
        count = len(normal_uids)
        noun = "email" if count == 1 else "emails"
        details, entity_id = _email_notification_details(store, folder, normal_uids)
        record_notification(
            title="New email received" if count == 1 else "New emails received",
            message=f"{count} new {noun} received.",
            kind="info",
            workspace="inbox",
            details=details,
            event_type="new-mail",
            entity_id=entity_id,
        )

    if spam_uids:
        count = len(spam_uids)
        noun = "email" if count == 1 else "emails"
        details, entity_id = _email_notification_details(store, folder, spam_uids)
        record_notification(
            title="Spam email detected" if count == 1 else "Spam emails detected",
            message=f"MailMind detected {count} spam {noun}.",
            kind="info",
            workspace="spam",
            details=details,
            event_type="security-spam",
            entity_id=entity_id,
        )

    # Critical external Security findings are grouped per publish/detection cycle
    # so a mixed burst (for example Phishing + Malware + Suspicious) creates one
    # Toast and one Bell entry instead of one pair per category/email.
    if high_risk_by_category:
        critical_uids = set().union(*high_risk_by_category.values())
        count = len(critical_uids)
        noun = "email" if count == 1 else "emails"
        category_details = [
            f"{_SECURITY_ALERT_CATEGORIES.get(category, category.title())}: {len(uids)}"
            for category, uids in sorted(high_risk_by_category.items())
        ]
        email_details, entity_id = _email_notification_details(
            store, folder, critical_uids, limit=SECURITY_ALERT_DETAIL_LIMIT
        )
        push_inbox_toast(
            f"MailMind detected {count} potentially harmful {noun}.",
            "security",
            title="Security alert",
            details=category_details + email_details,
            event_type="security-critical",
            entity_id=entity_id,
            notify_bell=True,
        )


def _release_published_new_mail(folder: str, published_uids) -> set[str]:
    # NEW mail is not user-visible until Security has completed and the store
    # publishes its final routed row. Only published Safe/Promotional Inbox mail
    # enters MailMind Unread; unsafe mail goes straight to Security/Spam.
    store = st.session_state.get("email_store")
    published = {str(uid) for uid in (published_uids or set()) if str(uid)}
    if store is None or not published:
        return set()

    pending = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }
    ready_new = published.intersection(pending)
    if not ready_new:
        return set()

    inbox_unread = {
        uid
        for uid in ready_new
        if (item := store.get_email(folder, uid)) is not None
        and not bool(item.get("is_spam"))
    }
    if inbox_unread:
        # MailMind Unread is durable app state, independent of the provider's
        # Seen flag. Persist it before updating Session State so F5/app reruns
        # cannot consume a newly published email.
        mark_unread = getattr(store, "mark_mailmind_unread", None)
        if callable(mark_unread):
            mark_unread(folder, inbox_unread)
        unread = {
            str(uid) for uid in st.session_state.get("new_email_uids", set()) if str(uid)
        }
        unread.update(inbox_unread)
        st.session_state.new_email_uids = unread

    routed_away = ready_new.difference(inbox_unread)
    if routed_away:
        mark_read = getattr(store, "mark_mailmind_read", None)
        if callable(mark_read):
            mark_read(folder, routed_away)

        # Spam -> Detected is the durable MailMind review queue for *all* newly
        # discovered unsafe findings, regardless of whether they came from the
        # old-mail Security catch-up path or from genuinely NEW incoming mail.
        # Opening the finding clears only this review state; it does not change
        # provider read/unread state or the final Security classification.
        newly_detected_unsafe = {
            uid
            for uid in routed_away
            if (item := store.get_email(folder, uid)) is not None
            and str(item.get("security_category") or "").strip().casefold() in {
                "spam", "phishing", "malware", "scam / fraud", "impersonation", "suspicious"
            }
        }
        mark_unreviewed = getattr(store, "mark_security_unreviewed", None)
        if newly_detected_unsafe and callable(mark_unreviewed):
            mark_unreviewed(folder, newly_detected_unsafe)

    # UI/Unread/Auto hand-off is per email, but Bell/Critical Toast grouping is
    # still per original mailbox detection cycle. Mark this subset ready now;
    # the cycle flush below waits only for its sibling UIDs' Security verdicts.
    _mark_new_mail_notification_ready(ready_new)

    # Auto Summary must be handed off at the same durable Security-publish
    # boundary as the NEW-mail Bell/Unread lifecycle.  Some NEW messages reach
    # this function through the high-priority recovery path after their first
    # full-message hydration was delayed.  That recovery path used to publish
    # the email to Inbox and clear the durable NEW marker without ever revisiting
    # the session-only Auto Summary staging queue, leaving an eligible visible
    # message permanently unsummarized until the user acted manually.
    #
    # Limit the queue decision to UIDs that were actually published in this
    # Security-finalized cycle.  Other staged NEW arrivals may still be waiting
    # for contextual Security and must stay out of the Summary queue.
    _queue_staged_auto_summary_after_security(folder, only_uids=ready_new)

    pending.difference_update(ready_new)
    st.session_state.pending_new_mail_notification_uids = pending
    _forget_durable_new_mail(folder, ready_new)
    _flush_completed_new_mail_notification_cycles(store, folder)
    return ready_new


def _auto_summary_enabled() -> bool:
    return bool(st.session_state.get("auto_summary_enabled"))


def _auto_summary_is_individual() -> bool:
    return (
        _auto_summary_enabled()
        and str(st.session_state.get("auto_summary_type_choice") or "Individual") == "Individual"
    )


def _stage_auto_summary_arrivals(
    new_uids, restored_uids, moved_to_inbox_uids=None
) -> None:
    # Auto Summary is triggered only by genuinely NEW mail. RESTORED mail and
    # provider Spam/Junk -> Inbox moves are lifecycle/location changes, not NEW
    # arrivals, so the restore itself must never start Auto Summary. Manual
    # summarization remains available later when Security/location eligibility
    # allows it.
    if not _auto_summary_enabled():
        return

    staged = dict(st.session_state.get("pending_auto_summary_arrivals", {}) or {})
    restored = {str(value) for value in (restored_uids or set()) if str(value)}
    restored.update(
        str(value) for value in (moved_to_inbox_uids or set()) if str(value)
    )
    # Clear stale restore/move entries left by older sessions/builds before
    # staging current genuine NEW arrivals.
    for uid in restored:
        staged.pop(uid, None)
    for uid in {str(value) for value in (new_uids or set()) if str(value)}:
        staged[uid] = "NEW"
    st.session_state.pending_auto_summary_arrivals = staged
    st.session_state.pending_auto_individual_arrivals = dict(staged)


# Backward-compatible name retained for the focused Step-2 regression runner.
def _stage_auto_individual_arrivals(new_uids, restored_uids, moved_to_inbox_uids=None) -> None:
    _stage_auto_summary_arrivals(new_uids, restored_uids, moved_to_inbox_uids)


def _hydrate_security_for_uids(folder: str, uids) -> int:
    # Folder moves are security-sensitive even when Auto Summary is disabled.
    # Hydrate any header-only moved/new rows before the visible Inbox is
    # published so an unsafe message never flashes in Inbox first.
    store = st.session_state.get("email_store")
    if store is None:
        return 0
    items = []
    for uid in {str(value) for value in (uids or set()) if str(value)}:
        header = store.get_email(folder, uid)
        if header is not None and int(header.get("security_input_version") or 0) < 2:
            items.append(header)
    if not items:
        return 0
    return len(_security_batch_for_items(items, folder))


def _incomplete_security_uids(folder: str, uids) -> set[str]:
    store = st.session_state.get("email_store")
    if store is None:
        return set()
    incomplete = set()
    for uid in {str(value) for value in (uids or set()) if str(value)}:
        header = store.get_email(folder, uid)
        if header is not None and int(header.get("security_input_version") or 0) < 2:
            incomplete.add(uid)
    return incomplete


def _refine_security_for_uids(folder: str, uids, *, genuine_new_uids=None) -> int:
    # Contextual AI is a second security layer after deterministic full-message
    # rules. Existing/restored/moved mail keeps the conservative old behavior:
    # only deterministic risk candidates are refined. Genuinely NEW mail is still
    # hidden by the publish gate, but obvious zero-risk Safe/Promotional verdicts
    # can now publish after deterministic full-message Security without paying an
    # unnecessary LLM round trip. Risky/ambiguous NEW verdicts still get the
    # contextual second opinion before publication.
    store = st.session_state.get("email_store")
    if store is None:
        return 0

    genuine_new = {
        str(value) for value in (genuine_new_uids or set()) if str(value)
    }
    items = []
    for uid in {str(value) for value in (uids or set()) if str(value)}:
        header = store.get_email(folder, uid)
        if header is None:
            continue
        refine = should_contextually_refine_security(
            category=str(header.get("security_category") or ""),
            source=str(header.get("security_source") or ""),
            security_input_version=int(header.get("security_input_version") or 0),
            genuine_new=uid in genuine_new,
            risk_score=int(header.get("spam_score") or 0),
        )
        trace_security_detection(
            "REFINEMENT_DECISION",
            mode="targeted",
            email=header,
            baseline=header,
            payload={"refine": bool(refine), "genuine_new": uid in genuine_new},
        )
        if not refine:
            continue
        items.append(header)

    if not items:
        return 0
    try:
        if not bool(get_ollama_status().get("model_ready")):
            return 0
    except Exception:
        return 0

    with security_trace_mode("targeted"):
        batch = _security_batch_for_items(items, folder)
    if not batch:
        return 0
    try:
        with security_trace_mode("targeted"):
            results = classify_email_security_batch(batch)
    except RuntimeError as error:
        print(f"[security] Targeted AI refinement skipped: {error}", flush=True)
        return 0

    updated = 0
    for uid, classification in results.items():
        if classification and store.update_security_classification(folder, uid, classification):
            updated += 1
    return updated



def _new_mail_security_refinement_active() -> bool:
    # Genuinely NEW mail may need a contextual AI second opinion before it is
    # published. Keep that expensive model request out of the Streamlit root run
    # so mailbox polling can never leave the browser waiting on a blank frame.
    future = st.session_state.get("new_mail_security_refinement_future")
    return bool(future is not None and not future.done())


def _run_new_mail_security_refinement(store, folder: str, batch: list[dict]) -> dict:
    # Worker-only model call. The deterministic full-message verdict has already
    # been persisted. IMPORTANT: the worker must not write the shared mailbox DB.
    # Returning the classifications lets the Streamlit UI thread apply the final
    # verdict and publish the row in one atomic hand-off. Otherwise a user can
    # briefly see a stale Inbox card/count while the worker has already rerouted
    # the same message underneath that cached UI. ``store`` is retained in the
    # signature for compatibility with existing worker launch/tests.
    _ = store
    _ = folder
    uids = {
        str((entry.get("email") or {}).get("uid") or "").strip()
        for entry in (batch or [])
        if str((entry.get("email") or {}).get("uid") or "").strip()
    }
    # NEW mail owns the next Security LLM slot. If one old catch-up request was
    # already inside Ollama when the arrival was detected, we let only that
    # in-flight request finish (it cannot be killed safely), then NEW mail runs
    # before catch-up is allowed to continue.
    with _SECURITY_LLM_EXECUTION_LOCK:
        try:
            with security_trace_mode("new_mail"):
                results = classify_email_security_batch(batch)
        except RuntimeError as error:
            trace_security_detection(
                "AI_BATCH_ERROR", mode="new_mail", payload={"error": str(error), "folder": folder}
            )
            print(f"[security] NEW-mail contextual refinement skipped: {error}", flush=True)
            results = {}

    classifications = {
        str(uid): dict(classification)
        for uid, classification in (results or {}).items()
        if str(uid) and classification
    }
    return {
        "completed_uids": sorted(uids),
        "classifications": classifications,
    }


def _start_new_mail_security_refinement(folder: str, uids) -> set[str]:
    # NEW mail has strict priority over old-mail catch-up. Every genuinely NEW
    # full-message row that still needs contextual review is queued here and
    # remains hidden until its own review completes. If another NEW-mail worker
    # is already running, later arrivals join the waiting queue instead of being
    # accidentally published from deterministic Security alone.
    normalized = {str(uid) for uid in (uids or set()) if str(uid)}
    if not normalized:
        return set()

    store = st.session_state.get("email_store")
    if store is None:
        return set()

    review_uids = set()
    for uid in sorted(normalized):
        header = store.get_email(folder, uid)
        if header is None:
            continue
        refine = should_contextually_refine_security(
            category=str(header.get("security_category") or ""),
            source=str(header.get("security_source") or ""),
            security_input_version=int(header.get("security_input_version") or 0),
            genuine_new=True,
            risk_score=int(header.get("spam_score") or 0),
        )
        trace_security_detection(
            "REFINEMENT_DECISION",
            mode="new_mail",
            email=header,
            baseline=header,
            payload={"refine": bool(refine), "genuine_new": True},
        )
        if refine:
            review_uids.add(uid)

    if not review_uids:
        return set()

    try:
        if not bool(get_ollama_status().get("model_ready")):
            return set()
    except Exception:
        return set()

    waiting = _new_mail_security_waiting_uids()
    waiting.update(review_uids)
    st.session_state.new_mail_security_waiting_uids = waiting
    _preempt_security_catchup_for_new_mail()

    # An active NEW-mail worker already owns the model. Keep these arrivals
    # hidden and let _finish_new_mail_security_refinement launch the next queue.
    if _new_mail_security_refinement_active():
        return review_uids

    # Publish progressively: one contextual Security request owns exactly one
    # genuinely NEW email. As soon as that verdict finishes, the monitor
    # publishes/reroutes that row and refreshes the thread list before launching
    # the next waiting email. This keeps Security-first routing intact without
    # making the first email wait for an entire burst.
    items = []
    ordered_waiting = []
    for uid in waiting:
        header = store.get_email(folder, uid)
        if header is not None:
            ordered_waiting.append(header)
    ordered_waiting.sort(
        key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or ""))
    )
    if ordered_waiting:
        items.append(ordered_waiting[0])

    with security_trace_mode("new_mail"):
        batch = _security_batch_for_items(items, folder)
    if not batch:
        # Do not strand rows whose full input unexpectedly disappeared. Remove
        # only those we could not stage; callers may publish their durable
        # deterministic full-message result.
        waiting.difference_update(review_uids)
        st.session_state.new_mail_security_waiting_uids = waiting
        return set()

    scheduled = {
        str((entry.get("email") or {}).get("uid") or "").strip()
        for entry in batch
        if str((entry.get("email") or {}).get("uid") or "").strip()
    }
    if not scheduled:
        return set()

    waiting.difference_update(scheduled)
    st.session_state.new_mail_security_waiting_uids = waiting
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="new-mail-security")
    st.session_state.new_mail_security_refinement_executor = executor
    st.session_state.new_mail_security_refinement_uids = set(scheduled)
    st.session_state.new_mail_security_refinement_future = executor.submit(
        _run_new_mail_security_refinement,
        store,
        folder,
        batch,
    )
    return review_uids


def _finish_new_mail_security_refinement(folder: str) -> bool:
    # Fast UI-thread commit only: the worker performs the model request but never
    # mutates the mailbox database. Apply its classification here, immediately
    # before publication, so routing + visibility + Auto Summary eligibility are
    # committed together and the Inbox cannot expose a transient stale thread.
    future = st.session_state.get("new_mail_security_refinement_future")
    if future is None or not future.done():
        return False

    scheduled = {
        str(uid)
        for uid in st.session_state.get("new_mail_security_refinement_uids", set())
        if str(uid)
    }
    classifications = {}
    try:
        result = future.result()
        completed = {
            str(uid) for uid in result.get("completed_uids", []) if str(uid)
        }
        if completed:
            scheduled.intersection_update(completed)
        classifications = {
            str(uid): dict(classification)
            for uid, classification in dict(result.get("classifications") or {}).items()
            if str(uid) and classification
        }
    except Exception as error:
        # Deterministic full-message Security is already durable, so even an
        # unexpected worker failure must not strand hidden NEW mail indefinitely.
        print(f"[security] NEW-mail contextual worker failed: {error}", flush=True)
    finally:
        executor = st.session_state.pop("new_mail_security_refinement_executor", None)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        st.session_state.pop("new_mail_security_refinement_future", None)
        st.session_state.pop("new_mail_security_refinement_uids", None)

    store = st.session_state.get("email_store")
    if store is not None and scheduled:
        # Apply only the classifications belonging to this scheduled NEW-mail
        # hand-off. Missing/failed AI results intentionally keep the durable
        # deterministic full-message verdict already stored for that UID.
        for uid in sorted(scheduled):
            classification = classifications.get(uid)
            if classification:
                store.update_security_classification(folder, uid, classification)

    published = (
        store.publish_security_ready(folder, scheduled)
        if store is not None and scheduled else set()
    )
    if published:
        for uid in sorted(published):
            header = store.get_email(folder, uid) if store is not None else None
            trace_security_detection(
                "NEW_MAIL_PUBLISHED",
                mode="new_mail",
                email=header or {"uid": uid},
                classification=header or {},
                payload={"folder": folder},
            )
        _release_published_new_mail(folder, published)
        recovered = {
            str(uid)
            for uid in st.session_state.get("new_mail_security_recovery_uids", set())
            if str(uid)
        }
        recovered.difference_update(published)
        st.session_state.new_mail_security_recovery_uids = recovered
    _hydrate_staged_auto_individual_security(folder)

    # Later NEW arrivals may have queued while this model request was running.
    # Start them before lower-priority catch-up/Auto Summary can reclaim Ollama.
    waiting = _new_mail_security_waiting_uids()
    if waiting:
        _start_new_mail_security_refinement(folder, waiting)

    if not _new_mail_security_priority_active():
        _queue_staged_auto_individual_after_security(folder)
    if published:
        st.session_state.inbox_loaded_view_signature = None
    remaining_pending = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }
    if remaining_pending and not _new_mail_security_refinement_active():
        st.session_state.new_mail_security_retry_at = min(
            float(st.session_state.get("new_mail_security_retry_at", 0.0) or 0.0) or time.time(),
            time.time(),
        )
    return bool(published)


def process_pending_new_mail_security(folder: str = "INBOX") -> bool:
    # High-priority recovery path for hidden NEW mail. A provider/full-message
    # hydration can transiently fail (especially if an older catch-up request was
    # already using the provider). Never leave that row stranded at ui_visible=0
    # and let generic old-mail catch-up decide when it gets another chance.
    if (
        not st.session_state.get("logged_in")
        or st.session_state.get("app_loading_active")
        or st.session_state.get("summary_processing")
        or st.session_state.get("draft_processing")
        or st.session_state.get("mailbox_sync_in_progress")
        or _new_mail_security_refinement_active()
    ):
        return False

    now = time.time()
    retry_at = float(st.session_state.get("new_mail_security_retry_at", 0.0) or 0.0)
    if retry_at > now:
        return False

    store = st.session_state.get("email_store")
    if store is None:
        return False

    pending, recovery = _recover_hidden_new_mail_state(folder)
    work_uids = pending.union(recovery)
    if not work_uids:
        st.session_state.new_mail_security_retry_at = 0.0
        return False

    _preempt_security_catchup_for_new_mail()

    # Retry full-message Security first. publish_security_ready() deliberately
    # refuses version<2 rows, so incomplete staged mail stays hidden until this
    # succeeds instead of being silently lost after one failed refresh/session.
    incomplete_before = _incomplete_security_uids(folder, work_uids)
    if incomplete_before:
        _hydrate_security_for_uids(folder, incomplete_before)

    incomplete_after = _incomplete_security_uids(folder, work_uids)
    ready = work_uids.difference(incomplete_after)
    background_uids = _start_new_mail_security_refinement(folder, ready)

    publish_now = ready.difference(background_uids)
    published = store.publish_security_ready(folder, publish_now) if publish_now else set()
    if published:
        # Only durable/session-confirmed genuine NEW UIDs release Unread/Bell/Auto
        # semantics. Orphan rows recovered solely from ui_visible=0 are published
        # safely without replaying a possibly old lifecycle event.
        _release_published_new_mail(folder, published)
        recovered = {
            str(uid)
            for uid in st.session_state.get("new_mail_security_recovery_uids", set())
            if str(uid)
        }
        recovered.difference_update(published)
        st.session_state.new_mail_security_recovery_uids = recovered
        st.session_state.inbox_loaded_view_signature = None

    # Any still-incomplete staged mail remains a high-priority retry, ahead of
    # catch-up. Use a small backoff so a temporarily busy provider is retried
    # without creating a tight full-app rerun loop.
    still_pending = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }
    still_recovery = {
        str(uid)
        for uid in st.session_state.get("new_mail_security_recovery_uids", set())
        if str(uid)
    }
    still_incomplete = _incomplete_security_uids(
        folder, still_pending.union(still_recovery)
    )
    if still_incomplete:
        st.session_state.new_mail_security_retry_at = time.time() + NEW_MAIL_SECURITY_RETRY_SECONDS
    elif not _new_mail_security_refinement_active() and not _new_mail_security_waiting_uids():
        st.session_state.new_mail_security_retry_at = 0.0

    return bool(published)


@st.fragment(run_every=NEW_MAIL_SECURITY_FRAGMENT_SECONDS)
def monitor_new_mail_security_refinement(folder: str = "INBOX") -> None:
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return
    # A fragment also runs inline during every full-app rerun. Consume a finished
    # future only on a later timer tick, never while the root page is still
    # mounting. This mirrors the proven Security catch-up generation gate.
    if not st.session_state.get("logged_in"):
        return
    if (
        st.session_state.get("app_loading_active")
        or st.session_state.get("summary_processing")
        or st.session_state.get("draft_processing")
    ):
        return

    generation = int(st.session_state.get("app_run_generation", 0) or 0)
    seen_generation = int(
        st.session_state.get("new_mail_security_monitor_seen_generation", -1) or -1
    )
    if seen_generation != generation:
        st.session_state.new_mail_security_monitor_seen_generation = generation
        return

    if _finish_new_mail_security_refinement(folder):
        st.rerun(scope="app")
        return

    # No active worker may simply mean the NEW row is still header-only because
    # its first full-message fetch lost a race with low-priority catch-up. Wake a
    # normal app run when the retry window opens; provider/DB work remains outside
    # the fragment itself.
    if not _new_mail_security_refinement_active():
        pending = {
            str(uid)
            for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid)
        }
        recovery = {
            str(uid)
            for uid in st.session_state.get("new_mail_security_recovery_uids", set())
            if str(uid)
        }
        retry_at = float(st.session_state.get("new_mail_security_retry_at", 0.0) or 0.0)
        if (pending or recovery) and time.time() >= retry_at:
            st.rerun(scope="app")


def _hydrate_staged_auto_summary_security(folder: str) -> int:
    if not _auto_summary_enabled():
        return 0
    staged = dict(st.session_state.get("pending_auto_summary_arrivals", {}) or {})
    if not staged:
        staged = dict(st.session_state.get("pending_auto_individual_arrivals", {}) or {})
        if staged:
            st.session_state.pending_auto_summary_arrivals = dict(staged)
    return _hydrate_security_for_uids(folder, staged)


# Backward-compatible name retained for existing tests/callers.
def _hydrate_staged_auto_individual_security(folder: str) -> int:
    return _hydrate_staged_auto_summary_security(folder)


def _summary_exists_for_header(header: dict, folder: str) -> bool:
    # Use the same physical-message identity contract as restoration/manual
    # duplicate protection. This prevents a restored or moved message from
    # generating a second summary when an existing summary already represents it.
    uid = str((header or {}).get("uid") or "").strip()
    for record in _summary_identity_records(folder):
        record_uids = {
            str(value or "").strip()
            for value in ([record.get("uid")] + list(record.get("source_uids") or []))
            if str(value or "").strip()
        }
        if uid and uid in record_uids:
            return True
        if same_message_identity(header, record):
            return True
    return False


def _queue_staged_auto_summary_after_security(
    folder: str, *, only_uids=None
) -> set[str]:
    # Shared Security-first queue gate for Auto Individual and Auto Batch. Only
    # Safe/Misclassified or Promotional messages whose CURRENT provider location
    # is Inbox may enter the queue. RESTORED mail is never an Auto arrival.
    staged = dict(st.session_state.get("pending_auto_summary_arrivals", {}) or {})
    if not staged:
        staged = dict(st.session_state.get("pending_auto_individual_arrivals", {}) or {})
        if staged:
            st.session_state.pending_auto_summary_arrivals = dict(staged)
    if not staged:
        return set()
    if not _auto_summary_enabled():
        st.session_state.pending_auto_summary_arrivals = {}
        st.session_state.pending_auto_individual_arrivals = {}
        return set()

    store = st.session_state.get("email_store")
    if store is None:
        return set()

    eligible = set()
    waiting = {}
    lifecycle_by_uid = dict(st.session_state.get("pending_auto_summary_lifecycle", {}) or {})
    allowed = (
        {str(uid) for uid in (only_uids or set()) if str(uid)}
        if only_uids is not None
        else None
    )
    for uid, lifecycle in staged.items():
        uid = str(uid)
        if allowed is not None and uid not in allowed:
            # Preserve unrelated staged arrivals exactly as-is.  They may still
            # be hidden behind NEW-mail Security and are intentionally not
            # eligible for this publish-cycle handoff.
            waiting[uid] = str(lifecycle or "NEW").strip().upper()
            continue
        lifecycle_name = str(lifecycle or "NEW").strip().upper()
        if lifecycle_name in {"RESTORED", "MOVED_SPAM_TO_INBOX"}:
            # Defensive cleanup for stale sessions created by older builds:
            # provider restoration/movement back to Inbox is lifecycle-only and
            # must never enter the automatic-summary arrival path.
            continue
        header = store.get_email(folder, str(uid))
        if header is None:
            continue
        if int(header.get("security_input_version") or 0) < 2:
            waiting[str(uid)] = lifecycle_name
            continue

        result = evaluate_summary_eligibility(
            header,
            lifecycle_state=lifecycle_name,
            already_summarized=_summary_exists_for_header(header, folder),
        )
        if result.can_generate:
            eligible.add(str(uid))
            lifecycle_by_uid[str(uid)] = lifecycle_name
        elif result.waiting_for_security:
            waiting[str(uid)] = lifecycle_name

    st.session_state.pending_auto_summary_arrivals = waiting
    st.session_state.pending_auto_individual_arrivals = dict(waiting)
    st.session_state.pending_auto_summary_lifecycle = lifecycle_by_uid
    if eligible:
        # Auto queueing is an internal background transition, not a user-facing
        # notification. The final Auto Summary result is Bell-only.
        _queue_auto_summary_uids(eligible)
    return eligible


# Backward-compatible Step-2 name.
def _queue_staged_auto_individual_after_security(folder: str) -> set[str]:
    return _queue_staged_auto_summary_after_security(folder)


def _relink_summary_uids(folder: str, relinks) -> None:
    normalized = [
        (str(old_uid or "").strip(), str(new_uid or "").strip())
        for old_uid, new_uid in (relinks or [])
        if str(old_uid or "").strip() and str(new_uid or "").strip()
        and str(old_uid or "").strip() != str(new_uid or "").strip()
    ]
    if not normalized:
        return

    # Reuse the security/body cache for a proven same-message UID transition.
    # This keeps RESTORED and Inbox <-> Spam/Junk moves lifecycle-only events:
    # a completed classification follows the physical email instead of being
    # recomputed merely because the provider exposed a different UID.
    email_store = st.session_state.get("email_store")
    if email_store is not None:
        for old_uid, new_uid in normalized:
            try:
                email_store.copy_security_state(folder, old_uid, new_uid)
            except Exception as error:
                print(
                    f"[security] Could not reuse security state {old_uid} -> {new_uid}: {error}",
                    flush=True,
                )

    summary_store = st.session_state.get("summary_store")
    if summary_store is None:
        return
    selected_summary_uid = str(st.session_state.get("selected_summary_uid") or "").strip()
    relink_map = dict(normalized)
    for old_uid, new_uid in normalized:
        summary_store.relink_uid(folder, old_uid, new_uid)
    st.session_state.summaries = summary_store.load_all(folder)
    if selected_summary_uid in relink_map:
        st.session_state.selected_summary_uid = relink_map[selected_summary_uid]


def _detect_cross_uid_location_transitions(folder: str, arrival_uids, missing_uids):
    # Gmail/IMAP folder moves can replace the folder-scoped UID. Detect those
    # moves after the new header is cached and before missing rows are announced
    # as deletions. Outlook normally reports the same transition in-place.
    store = st.session_state.get("email_store")
    if store is None:
        return detect_cross_uid_provider_moves([], [])
    arrivals = [
        item for uid in {str(value) for value in (arrival_uids or set()) if str(value)}
        if (item := store.get_email(folder, uid)) is not None
    ]
    missing = [
        item for uid in {str(value) for value in (missing_uids or set()) if str(value)}
        if (item := store.get_email(folder, uid, include_unavailable=True)) is not None
    ]
    transitions = detect_cross_uid_provider_moves(arrivals, missing)
    _relink_summary_uids(folder, transitions.relinks)

    # Retire the old folder-scoped UID from live UI/queue state. Without this,
    # a Gmail Inbox -> Spam move could leave the unavailable old safe UID in the
    # MailMind Unread count or let a stale Auto Summary job continue.
    retired = {str(old_uid) for old_uid, _new_uid in transitions.relinks if str(old_uid)}
    if retired:
        mark_read = getattr(store, "mark_mailmind_read", None)
        if callable(mark_read):
            mark_read(folder, retired)
        st.session_state.new_email_uids = {
            str(uid) for uid in st.session_state.get("new_email_uids", set())
            if str(uid) and str(uid) not in retired
        }
        st.session_state.checked_uids = {
            str(uid) for uid in st.session_state.get("checked_uids", set())
            if str(uid) and str(uid) not in retired
        }
        if str(st.session_state.get("selected_uid") or "") in retired:
            st.session_state.selected_uid = None
        _drop_auto_summary_uids(retired)

    return transitions


def _drop_auto_summary_uids(uids) -> None:
    blocked = {str(uid) for uid in (uids or set()) if str(uid)}
    if not blocked:
        return
    st.session_state.pending_auto_summary_uids = {
        str(uid) for uid in st.session_state.get("pending_auto_summary_uids", set())
        if str(uid) and str(uid) not in blocked
    }
    staged = dict(st.session_state.get("pending_auto_summary_arrivals", {}) or {})
    for uid in blocked:
        staged.pop(uid, None)
    st.session_state.pending_auto_summary_arrivals = staged
    st.session_state.pending_auto_individual_arrivals = dict(staged)
    lifecycle = dict(st.session_state.get("pending_auto_summary_lifecycle", {}) or {})
    for uid in blocked:
        lifecycle.pop(uid, None)
    st.session_state.pending_auto_summary_lifecycle = lifecycle


def _publish_provider_move_state_after_security(folder: str, moved_to_inbox_uids, moved_to_spam_uids) -> None:
    # Provider Inbox <-> Spam/Junk movement is a location/lifecycle change, not a
    # NEW-mail event. It must never manufacture MailMind Unread state. Moving an
    # item to Spam removes it from Inbox attention; restoring it to Inbox keeps
    # it read unless it was independently marked Unread by a genuine NEW arrival.
    store = st.session_state.get("email_store")
    if store is None:
        return
    moved_in = {str(uid) for uid in (moved_to_inbox_uids or set()) if str(uid)}
    moved_spam = {str(uid) for uid in (moved_to_spam_uids or set()) if str(uid)}

    unread = {str(uid) for uid in st.session_state.get("new_email_uids", set()) if str(uid)}
    unread.difference_update(moved_spam)

    # A provider restore/move is lifecycle-only, never a genuinely NEW arrival.
    # Remove both directions from NEW-notification/Auto queues defensively so an
    # old session or race cannot promote a restored message into NEW behavior.
    moved_lifecycle = moved_in.union(moved_spam)
    _drop_auto_summary_uids(moved_lifecycle)
    _forget_durable_new_mail(folder, moved_lifecycle)
    pending_notifications = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }
    pending_notifications.difference_update(moved_lifecycle)
    st.session_state.pending_new_mail_notification_uids = pending_notifications
    if moved_in:
        restored_state = {
            str(uid)
            for uid in st.session_state.get("restored_email_uids", set())
            if str(uid)
        }
        restored_state.update(moved_in)
        st.session_state.restored_email_uids = restored_state

    # A provider restore does not make the message NEW or Unread. Security still
    # decides whether it is allowed back into Inbox, but the location change does
    # not alter the user's MailMind read/viewed state. Defensive cleanup removes
    # stale NEW markers for both directions so older session state cannot revive
    # a restored message as Unread.
    unread.difference_update(moved_in)
    st.session_state.new_email_uids = unread

    moved_read = moved_spam.union(moved_in)
    if moved_read:
        mark_read = getattr(store, "mark_mailmind_read", None)
        if callable(mark_read):
            mark_read(folder, moved_read)

    # The provider-location Bell is recorded at reconciliation time, before
    # Security hydration/refinement. This function only publishes the resulting
    # lifecycle state. Keeping notification recording out of this late stage
    # prevents a rerun/provider failure from silently losing a real external move.


def _remember_provider_moves(moved_to_inbox_uids, moved_to_spam_uids) -> None:
    inbox_moves = {
        str(uid) for uid in st.session_state.get("pending_provider_moved_to_inbox_uids", set()) if str(uid)
    }
    spam_moves = {
        str(uid) for uid in st.session_state.get("pending_provider_moved_to_spam_uids", set()) if str(uid)
    }
    inbox_moves.update(str(uid) for uid in (moved_to_inbox_uids or set()) if str(uid))
    spam_moves.update(str(uid) for uid in (moved_to_spam_uids or set()) if str(uid))
    inbox_moves.difference_update(spam_moves)
    spam_moves.difference_update(inbox_moves)
    st.session_state.pending_provider_moved_to_inbox_uids = inbox_moves
    st.session_state.pending_provider_moved_to_spam_uids = spam_moves


def _consume_provider_moves() -> tuple[set[str], set[str]]:
    moved_in = {
        str(uid) for uid in st.session_state.pop("pending_provider_moved_to_inbox_uids", set()) if str(uid)
    }
    moved_spam = {
        str(uid) for uid in st.session_state.pop("pending_provider_moved_to_spam_uids", set()) if str(uid)
    }
    return moved_in, moved_spam


def _queue_auto_summary_uids(new_uids) -> bool:
    # Queue new mail and return True when a fresh Auto Batch window starts.
    if not st.session_state.get("auto_summary_enabled"):
        return False
    normalized = {str(uid) for uid in (new_uids or set()) if str(uid)}
    if not normalized:
        return False
    pending = {
        str(uid)
        for uid in st.session_state.get("pending_auto_summary_uids", set())
        if str(uid)
    }
    queue_was_empty = not pending
    pending.update(normalized)
    st.session_state.pending_auto_summary_uids = pending

    now = time.time()
    st.session_state.auto_summary_queue_updated_at = now
    auto_type = str(st.session_state.get("auto_summary_type_choice") or "Individual")

    if auto_type == "Batch":
        # A Batch collection window begins with the first queued message and does
        # not reset for every later arrival. This gives nearby messages a chance
        # to join one batch without allowing a busy inbox to postpone forever.
        started_at = float(st.session_state.get("auto_summary_batch_started_at", 0.0) or 0.0)
        deadline = float(st.session_state.get("auto_summary_batch_deadline", 0.0) or 0.0)
        if queue_was_empty or started_at <= 0 or deadline <= 0:
            wait_seconds = AUTO_BATCH_WAIT_SECONDS
            started_at = now
            deadline = now + wait_seconds
            st.session_state.auto_summary_batch_started_at = started_at
            st.session_state.auto_summary_batch_deadline = deadline
        st.session_state.auto_summary_not_before = deadline
        st.session_state.auto_summary_start_requested = False
    else:
        # Individual Auto Summary has no reason to wait on a second timer after
        # Security has already finalized and published the NEW email. Request the
        # worker handoff immediately; the normal app rerun after publication will
        # consume it. If that root run is temporarily paused by a foreground
        # interaction, the Auto monitor re-wakes the app once the settle guard
        # clears instead of silently starving the queue.
        st.session_state.auto_summary_batch_started_at = 0.0
        st.session_state.auto_summary_batch_deadline = 0.0
        st.session_state.auto_summary_not_before = now
        st.session_state.auto_summary_start_requested = True

    return bool(auto_type == "Batch" and queue_was_empty)


def _load_current_inbox_view(folder: str) -> None:
    search_mode = bool(st.session_state.get("search_active"))
    query = (
        str(st.session_state.get("inbox_search_query", "") or "").strip()
        if search_mode
        else ""
    )
    st.session_state.inbox_loaded_view_signature = None
    load_local_page(
        0,
        folder,
        search_mode=search_mode,
        query=query,
    )


def _fetch_new_header_pages(
    folder: str,
    known_uids: set[str],
    *,
    client=None,
    store=None,
) -> dict:
    # The unified security mailbox is Inbox + Spam/Junk only. Ask the provider
    # to inspect those two sources independently so custom/archive folders are
    # never scanned and a new Spam message cannot be hidden behind Inbox pages.
    # Optional explicit dependencies let the automatic mailbox-sync worker do
    # provider I/O outside the Streamlit foreground run without touching
    # ``st.session_state`` from its background thread.
    client = client if client is not None else st.session_state.imap_client
    store = store if store is not None else st.session_state.email_store
    if (
        str(folder or "").upper() == str(getattr(client, "ALL_MAIL", "")).upper()
        and callable(getattr(client, "fetch_recent_security_headers", None))
    ):
        result = refresh_security_changes(
            client,
            known_uids,
            store,
            folder,
            page_size=MAILBOX_SYNC_PAGE_SIZE,
            max_pages=20,
        )
        if not result.get("success"):
            return result
        return {
            "success": True,
            "new_uids": set(result.get("new_uids", set())).difference(known_uids),
            "total": int(result.get("total", 0) or 0),
        }

    # Single-folder fallback: fetch newest header pages until the first
    # already-cached UID is reached.
    collected_new: set[str] = set()
    last_result = None
    offset = 0

    # Twenty 250-message pages covers an unusually large burst while still
    # protecting the UI session from an unbounded background sync.
    for page_index in range(20):
        result = refresh_inbox(
            client,
            limit=MAILBOX_SYNC_PAGE_SIZE,
            offset=offset,
            refresh=(page_index == 0),
            store=store,
            folder=folder,
            sync_source="automatic_mailbox_monitor",
            reconcile=False,
        )
        if not result.get("success"):
            return result

        last_result = result
        page_uids = {
            str(item.get("uid") or "")
            for item in result.get("emails", [])
            if str(item.get("uid") or "")
        }
        collected_new.update(page_uids.difference(known_uids))

        # New mail is ordered first. Once a page includes a known UID, all
        # older pages are already represented in the local cache.
        if page_uids.intersection(known_uids):
            break
        if not result.get("has_more") or not page_uids:
            break
        offset += len(result.get("emails", []))

    return {
        "success": True,
        "new_uids": collected_new,
        "total": int((last_result or {}).get("total", 0) or 0),
    }


def _sync_detected_mailbox_changes(
    folder: str,
    remote_count: int,
    now: float,
    activity_slot=None,
    force_location_reconcile: bool = False,
) -> bool:
    store = st.session_state.email_store
    client = st.session_state.imap_client
    before_uids = store.get_active_uids(folder)
    unavailable_uids_before = store.get_unavailable_uids(folder)
    local_count = len(before_uids)
    remote_count_baseline = _mailbox_remote_count_baseline(store, folder, local_count)
    last_reconcile = float(st.session_state.get("last_mail_reconcile", 0.0) or 0.0)
    periodic_reconcile_due = (now - last_reconcile) >= MAILBOX_RECONCILE_SECONDS
    new_uids: set[str] = set()
    moved_to_inbox_uids: set[str] = set()
    moved_to_spam_uids: set[str] = set()
    removed = 0
    reconciliation = None

    new_mail_progress = None
    if remote_count > remote_count_baseline:
        expected_count = max(remote_count - remote_count_baseline, 1)
        noun = "email" if expected_count == 1 else "emails"
        new_mail_progress = start_sidebar_activity(
            activity_slot,
            f"Retrieving {expected_count} new {noun}...",
            0.18,
        )
        try:
            update_sidebar_activity(
                new_mail_progress, 0.42, "Downloading new email headers..."
            )
            fetch_result = _fetch_new_header_pages(folder, before_uids)
            if not fetch_result.get("success"):
                error = fetch_result.get("error", "Unknown error")
                _record_background_connection_issue(error)
                print(
                    f"[mail-monitor] Automatic new-mail sync skipped: "
                    f"{error}",
                    flush=True,
                )
                return False
            new_uids.update(fetch_result.get("new_uids", set()))
            update_sidebar_activity(new_mail_progress, 0.78, "Updating the Inbox...")
        finally:
            if activity_slot is not None:
                clear_sidebar_activity(activity_slot)

    # Folder moves can keep the combined Inbox+Spam count unchanged. The normal
    # periodic reconciliation detects those location transitions; manual Refresh
    # performs the same comparison immediately.
    if (
        remote_count < remote_count_baseline
        or periodic_reconcile_due
        or force_location_reconcile
    ):
        reconciliation = reconcile_folder(client, store, folder)
        st.session_state.last_mail_reconcile = now
        if reconciliation.success:
            moved_to_inbox_uids.update(reconciliation.moved_to_inbox_uids)
            moved_to_spam_uids.update(reconciliation.moved_to_spam_uids)

            unknown_remote = set(reconciliation.remote_uids).difference(before_uids)
            if unknown_remote.difference(new_uids):
                fetch_result = _fetch_new_header_pages(folder, before_uids)
                if fetch_result.get("success"):
                    new_uids.update(fetch_result.get("new_uids", set()))

            # Gmail/IMAP can assign a new folder-scoped UID on Inbox <-> Spam
            # moves. Recognize the same physical message before treating the old
            # UID as a deletion or the new UID as new mail.
            transitions = _detect_cross_uid_location_transitions(
                folder, new_uids, reconciliation.missing_uids
            )
            moved_to_inbox_uids.update(transitions.moved_to_inbox)
            moved_to_spam_uids.update(transitions.moved_to_spam)
            new_uids.difference_update(transitions.consumed_arrival_uids)
            true_missing = set(reconciliation.missing_uids).difference(
                transitions.consumed_missing_uids
            )
            removed = apply_confirmed_deletions(true_missing)
        else:
            _record_background_connection_issue(reconciliation.error)
            print(
                f"[mail-monitor] Deletion reconciliation skipped: {reconciliation.error}",
                flush=True,
            )

    after_uids = store.get_active_uids(folder)
    discovered = after_uids.difference(before_uids)
    discovered.difference_update(moved_to_inbox_uids)
    discovered.difference_update(moved_to_spam_uids)
    new_uids.update(discovered)

    restored_uids, new_uids = _classify_arrivals(
        folder, new_uids, unavailable_uids_before
    )
    _notify_restored_emails(store, folder, restored_uids)
    # Record provider Inbox <-> Spam/Junk movement as soon as reconciliation has
    # proven it. The Bell describes the provider-side lifecycle event itself, so
    # it does not need to wait for MailMind's later Security publication.
    _notify_provider_location_moves(
        store, folder, moved_to_inbox_uids, moved_to_spam_uids
    )

    # Persist the NEW lifecycle hand-off before the asynchronous Security worker
    # starts. A browser/WebSocket session replacement can then reconstruct the
    # exact pending NEW queue instead of leaving the hidden row stranded.
    if new_uids:
        _remember_durable_new_mail(folder, new_uids)

    _stage_auto_summary_arrivals(new_uids, restored_uids, moved_to_inbox_uids)
    _drop_auto_summary_uids(moved_to_spam_uids)
    _remember_provider_moves(moved_to_inbox_uids, moved_to_spam_uids)

    # Security is independent of Auto Summary. Genuine NEW mail always gets a
    # full deterministic check, while RESTORED/MOVED messages are hydrated only
    # when their persisted Security input is incomplete. Completed classifications
    # are reused and folder movement alone never triggers reclassification.
    security_hydration = {
        str(uid)
        for uid in st.session_state.get("pending_security_hydration_uids", set())
        if str(uid)
    }
    security_hydration.update(new_uids)
    security_hydration.update(restored_uids)
    security_hydration.update(moved_to_inbox_uids)
    security_hydration.update(moved_to_spam_uids)
    st.session_state.pending_security_hydration_uids = security_hydration

    if new_uids:
        # Stage NEW mail outside both Inbox and Spam UI. Unread state and user
        # notification are published only after full Security chooses the final
        # workspace, so an unsafe message can never flash in Inbox first.
        pending_notifications = {
            str(uid) for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid)
        }
        pending_notifications.update(new_uids)
        st.session_state.pending_new_mail_notification_uids = pending_notifications
        _register_new_mail_notification_cycle(new_uids)

    count_reconciliation_failed = bool(
        remote_count < remote_count_baseline
        and reconciliation is not None
        and not reconciliation.success
    )
    if not count_reconciliation_failed:
        store.update_remote_total(folder, remote_count)
    st.session_state.inbox_all_total = int(remote_count)
    st.session_state.new_mail_count = 0

    return bool(
        new_uids or restored_uids or moved_to_inbox_uids or moved_to_spam_uids or removed
    )


def _collect_pending_mailbox_sync_remote(
    client,
    store,
    folder: str,
    remote_count: int,
    now: float,
    force_location_reconcile: bool,
    last_reconcile: float,
) -> dict:
    """Perform provider-heavy automatic mailbox discovery off the UI thread."""
    before_uids = store.get_active_uids(folder)
    unavailable_uids_before = store.get_unavailable_uids(folder)
    local_count = len(before_uids)
    remote_count_baseline = _mailbox_remote_count_baseline(store, folder, local_count)
    periodic_reconcile_due = (now - float(last_reconcile or 0.0)) >= MAILBOX_RECONCILE_SECONDS
    new_uids: set[str] = set()
    reconciliation = None
    reconciliation_attempted = False

    if remote_count > remote_count_baseline:
        fetch_result = _fetch_new_header_pages(
            folder,
            before_uids,
            client=client,
            store=store,
        )
        if not fetch_result.get("success"):
            return {
                "success": False,
                "error": fetch_result.get("error", "Unknown mailbox sync error"),
            }
        new_uids.update(fetch_result.get("new_uids", set()))

    if (
        remote_count < remote_count_baseline
        or periodic_reconcile_due
        or force_location_reconcile
    ):
        reconciliation_attempted = True
        reconciliation = reconcile_folder(client, store, folder)
        if reconciliation.success:
            unknown_remote = set(reconciliation.remote_uids).difference(before_uids)
            if unknown_remote.difference(new_uids):
                fetch_result = _fetch_new_header_pages(
                    folder,
                    before_uids,
                    client=client,
                    store=store,
                )
                if fetch_result.get("success"):
                    new_uids.update(fetch_result.get("new_uids", set()))
        else:
            # Match the previous behavior: a reconciliation failure must not turn
            # into a deletion, but newly fetched headers can still be committed.
            pass

    after_uids = store.get_active_uids(folder)
    discovered = after_uids.difference(before_uids)
    new_uids.update(discovered)
    return {
        "success": True,
        "remote_count": int(remote_count),
        "remote_count_baseline": int(remote_count_baseline),
        "now": float(now),
        "before_uids": set(before_uids),
        "unavailable_uids_before": set(unavailable_uids_before),
        "new_uids": set(new_uids),
        "reconciliation": reconciliation,
        "reconciliation_attempted": bool(reconciliation_attempted),
    }


def _finish_pending_mailbox_sync(folder: str = "INBOX") -> bool:
    """Commit a completed automatic mailbox worker on the Streamlit UI thread."""
    future = st.session_state.get("mailbox_sync_future")
    if future is None or not future.done():
        return False

    expected_account = str(st.session_state.get("mailbox_sync_account") or "")
    current_account = str(
        st.session_state.get("active_store_account")
        or st.session_state.get("email_address")
        or ""
    )
    try:
        result = future.result()
    except Exception as error:
        result = {"success": False, "error": error}
    finally:
        executor = st.session_state.pop("mailbox_sync_executor", None)
        if executor is not None:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        st.session_state.pop("mailbox_sync_future", None)
        st.session_state.pop("mailbox_sync_account", None)
        st.session_state.mailbox_sync_in_progress = False

    # A logout/account switch may finish before the detached provider worker.
    # Never apply that stale result to the newly active mailbox session.
    if expected_account and current_account and expected_account != current_account:
        return False

    st.session_state.pop("pending_mailbox_remote_count", None)
    st.session_state.pop("pending_mailbox_detected_at", None)
    st.session_state.pop("pending_mailbox_location_change", None)

    if not result.get("success"):
        error = result.get("error", "Unknown mailbox sync error")
        _record_background_connection_issue(error)
        print(f"[mail-monitor] Pending new-mail sync failed: {error}", flush=True)
        return False

    mark_provider_connection_ok()
    store = st.session_state.get("email_store")
    if store is None:
        return False

    remote_count = int(result.get("remote_count") or 0)
    remote_count_baseline = int(result.get("remote_count_baseline") or 0)
    now = float(result.get("now") or time.time())
    before_uids = set(result.get("before_uids") or set())
    unavailable_uids_before = set(result.get("unavailable_uids_before") or set())
    new_uids = {str(uid) for uid in result.get("new_uids", set()) if str(uid)}
    reconciliation = result.get("reconciliation")

    moved_to_inbox_uids: set[str] = set()
    moved_to_spam_uids: set[str] = set()
    removed = 0
    if result.get("reconciliation_attempted"):
        st.session_state.last_mail_reconcile = now
    if reconciliation is not None:
        if reconciliation.success:
            moved_to_inbox_uids.update(
                str(uid) for uid in reconciliation.moved_to_inbox_uids if str(uid)
            )
            moved_to_spam_uids.update(
                str(uid) for uid in reconciliation.moved_to_spam_uids if str(uid)
            )
            transitions = _detect_cross_uid_location_transitions(
                folder, new_uids, reconciliation.missing_uids
            )
            moved_to_inbox_uids.update(transitions.moved_to_inbox)
            moved_to_spam_uids.update(transitions.moved_to_spam)
            new_uids.difference_update(transitions.consumed_arrival_uids)
            true_missing = set(reconciliation.missing_uids).difference(
                transitions.consumed_missing_uids
            )
            removed = apply_confirmed_deletions(true_missing)
        else:
            _record_background_connection_issue(reconciliation.error)
            print(
                f"[mail-monitor] Deletion reconciliation skipped: {reconciliation.error}",
                flush=True,
            )

    # The provider worker can cache headers while the user continues interacting.
    # Recompute discoveries at commit time so none of those arrivals are missed.
    after_uids = store.get_active_uids(folder)
    discovered = after_uids.difference(before_uids)
    discovered.difference_update(moved_to_inbox_uids)
    discovered.difference_update(moved_to_spam_uids)
    new_uids.update(discovered)

    restored_uids, new_uids = _classify_arrivals(
        folder, new_uids, unavailable_uids_before
    )
    _notify_restored_emails(store, folder, restored_uids)
    _notify_provider_location_moves(
        store, folder, moved_to_inbox_uids, moved_to_spam_uids
    )

    if new_uids:
        _remember_durable_new_mail(folder, new_uids)

    _stage_auto_summary_arrivals(new_uids, restored_uids, moved_to_inbox_uids)
    _drop_auto_summary_uids(moved_to_spam_uids)
    _remember_provider_moves(moved_to_inbox_uids, moved_to_spam_uids)

    security_hydration = {
        str(uid)
        for uid in st.session_state.get("pending_security_hydration_uids", set())
        if str(uid)
    }
    security_hydration.update(new_uids)
    security_hydration.update(restored_uids)
    security_hydration.update(moved_to_inbox_uids)
    security_hydration.update(moved_to_spam_uids)
    st.session_state.pending_security_hydration_uids = security_hydration

    if new_uids:
        pending_notifications = {
            str(uid)
            for uid in st.session_state.get("pending_new_mail_notification_uids", set())
            if str(uid)
        }
        pending_notifications.update(new_uids)
        st.session_state.pending_new_mail_notification_uids = pending_notifications
        _register_new_mail_notification_cycle(new_uids)

    count_reconciliation_failed = bool(
        remote_count < remote_count_baseline
        and reconciliation is not None
        and not reconciliation.success
    )
    if not count_reconciliation_failed:
        store.update_remote_total(folder, remote_count)
    st.session_state.inbox_all_total = int(remote_count)
    st.session_state.new_mail_count = 0

    moved_to_inbox_uids, moved_to_spam_uids = _consume_provider_moves()
    security_hydration_uids = {
        str(uid)
        for uid in st.session_state.pop("pending_security_hydration_uids", set())
        if str(uid)
    }
    security_hydration_uids.update(moved_to_inbox_uids)
    security_hydration_uids.update(moved_to_spam_uids)
    newly_incomplete = _incomplete_security_uids(folder, security_hydration_uids)
    _hydrate_security_for_uids(folder, security_hydration_uids)

    genuine_new_uids = {
        str(uid)
        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
        if str(uid)
    }.intersection(security_hydration_uids)
    synchronous_uids = newly_incomplete.difference(genuine_new_uids)
    _refine_security_for_uids(folder, synchronous_uids)
    background_uids = _start_new_mail_security_refinement(
        folder, genuine_new_uids
    )
    publish_now_uids = security_hydration_uids.difference(background_uids)
    published_uids = store.publish_security_ready(folder, publish_now_uids)
    _release_published_new_mail(folder, published_uids)
    _hydrate_staged_auto_individual_security(folder)
    _publish_provider_move_state_after_security(
        folder, moved_to_inbox_uids, moved_to_spam_uids
    )
    if not background_uids:
        _queue_staged_auto_individual_after_security(folder)

    _load_current_inbox_view(folder)
    return bool(
        new_uids
        or restored_uids
        or moved_to_inbox_uids
        or moved_to_spam_uids
        or removed
    )


def process_pending_mailbox_sync(activity_slot=None, folder: str = "INBOX") -> None:
    # Automatic provider/header reconciliation must never monopolize the full
    # Streamlit app run. Launch its network-heavy phase in a worker and commit the
    # durable result later on a stable root rerun. Existing Inbox/Spam cards remain
    # fully selectable while the worker is in flight.
    if (
        st.session_state.get("app_loading_active")
        or (
            st.session_state.get("summary_processing")
            and str(st.session_state.get("summary_job_origin") or "manual") != "auto"
        )
        or st.session_state.get("draft_processing")
        or _new_mail_security_refinement_active()
    ):
        return

    future = st.session_state.get("mailbox_sync_future")
    if future is not None:
        if not future.done():
            return
        if _finish_pending_mailbox_sync(folder):
            st.rerun()
        return

    pending_count = st.session_state.get("pending_mailbox_remote_count")
    if pending_count is None or st.session_state.get("mailbox_sync_in_progress"):
        return

    client = st.session_state.get("imap_client")
    store = st.session_state.get("email_store")
    if client is None or store is None:
        return

    _preempt_security_catchup_for_new_mail()
    st.session_state.mailbox_sync_in_progress = True
    account = str(
        st.session_state.get("active_store_account")
        or st.session_state.get("email_address")
        or ""
    )
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mailbox-sync")
    st.session_state.mailbox_sync_executor = executor
    st.session_state.mailbox_sync_account = account
    st.session_state.mailbox_sync_future = executor.submit(
        _collect_pending_mailbox_sync_remote,
        client,
        store,
        folder,
        int(pending_count),
        float(st.session_state.get("pending_mailbox_detected_at") or time.time()),
        bool(st.session_state.get("pending_mailbox_location_change")),
        float(st.session_state.get("last_mail_reconcile", 0.0) or 0.0),
    )


@st.fragment(run_every=MAILBOX_MONITOR_FRAGMENT_SECONDS)
def monitor_mailbox_changes(activity_slot=None, folder: str = "INBOX") -> None:
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return

    # A completed automatic sync is committed only from a stable full-app run.
    # Wake that run from the lightweight timer; do not apply provider/DB results
    # inside the fragment itself.
    sync_future = st.session_state.get("mailbox_sync_future")
    if sync_future is not None:
        if sync_future.done():
            st.rerun(scope="app")
        return

    # Poll mail only on this fragment's timer, never because the user clicked.
    # A fragment is also executed inline during every full-app rerun. Record
    # that generation and return immediately. On the fragment's later timer
    # rerun, app_run_generation is unchanged, so only then may we poll mail.
    generation = int(st.session_state.get("app_run_generation", 0) or 0)
    seen_generation = int(
        st.session_state.get("mailbox_monitor_seen_generation", -1) or -1
    )
    if seen_generation != generation:
        st.session_state.mailbox_monitor_seen_generation = generation
        return

    if not (
        st.session_state.get("logged_in")
        and st.session_state.get("inbox_loaded")
        and st.session_state.get("full_synced")
        and not st.session_state.get("loading")
        and not st.session_state.get("app_loading_active")
        and st.session_state.get("imap_client") is not None
        and st.session_state.get("email_store") is not None
    ):
        return

    now = time.time()
    last_check = float(st.session_state.get("last_mail_check", 0.0) or 0.0)
    if (now - last_check) < MAILBOX_POLL_SECONDS:
        return
    if st.session_state.get("mailbox_monitor_busy"):
        return

    st.session_state.last_mail_check = now
    st.session_state.mailbox_monitor_busy = True
    try:
        remote_count = st.session_state.imap_client.get_message_count(folder)
        if remote_count is None:
            return

        mark_provider_connection_ok()
        remote_count = int(remote_count)
        local_count = len(st.session_state.email_store.get_active_uids(folder))
        remote_count_baseline = _mailbox_remote_count_baseline(
            st.session_state.email_store, folder, local_count
        )

        # Detect Inbox <-> Spam/Junk moves from the per-folder counts already
        # collected by the lightweight message-count poll. A move can keep the
        # combined total unchanged, so total-only polling would otherwise wait for
        # the slow periodic reconciliation. This check adds no provider request.
        location_changed = False
        signature_getter = getattr(
            st.session_state.imap_client, "get_security_location_count_signature", None
        )
        if callable(signature_getter):
            current_signature = tuple(signature_getter() or ())
            if current_signature:
                # Compare against the cache's persisted provider locations, not
                # only the previous in-memory poll. This removes the first-poll
                # blind spot: if the user moves an email right after login, the
                # provider folder counts already differ from the local DB even
                # though no prior session signature exists yet. Restrict this to
                # unchanged combined totals so ordinary new/deleted mail keeps
                # using the lighter delta path.
                location_changed = bool(
                    remote_count == remote_count_baseline
                    and _provider_location_counts_changed(
                        st.session_state.email_store, folder, current_signature
                    )
                )
                st.session_state.mailbox_location_count_signature = current_signature

        # Timed fragments must only detect/schedule mailbox work. Running provider
        # sync, full-message Security hydration, SQLite publication, and an app
        # rerun from inside the fragment can overlap a normal Streamlit rerun and
        # intermittently leave the browser on an empty frame. Schedule every real
        # mailbox change/reconciliation for the normal app run instead.
        last_reconcile = float(st.session_state.get("last_mail_reconcile", 0.0) or 0.0)
        reconcile_due = (now - last_reconcile) >= MAILBOX_RECONCILE_SECONDS
        if remote_count != remote_count_baseline or reconcile_due or location_changed:
            if remote_count != remote_count_baseline:
                _preempt_security_catchup_for_new_mail()
            st.session_state.pending_mailbox_remote_count = remote_count
            st.session_state.pending_mailbox_detected_at = now
            if location_changed:
                st.session_state.pending_mailbox_location_change = True
            st.rerun(scope="app")
            return
    except Exception as error:
        _record_background_connection_issue(error)
        print(f"[mail-monitor] Mailbox check skipped: {error}", flush=True)
    finally:
        st.session_state.mailbox_monitor_busy = False


# Process search, refresh, and pagination actions.
def handle_inbox_actions(inbox_actions, activity_slot, folder: str = "INBOX"):
    query = (inbox_actions["query"] or "").strip()
    if inbox_actions["search"] and query:
        trace_action("inbox-search-process", query_len=len(query))
        search_progress = start_sidebar_activity(
            activity_slot, "Searching saved mail...", 0.12
        )
        st.session_state.search_active = True
        st.session_state.inbox_search_offset = 0
        st.session_state.selected_uid = None
        update_sidebar_activity(
            search_progress, 0.72, "Applying filters to the complete inbox..."
        )
        if load_local_page(
            0,
            folder,
            search_mode=True,
            query=query,
        ):
            finish_sidebar_activity(search_progress, "Search complete")
        clear_sidebar_activity(activity_slot)
        st.session_state.foreground_navigation_guard = True
        arm_foreground_interaction()
        st.rerun()

    if inbox_actions["clear_search"]:
        trace_action("inbox-search-clear")
        st.session_state.search_active = False
        st.session_state.search_results = []
        st.session_state.search_total = 0
        st.session_state.inbox_search_offset = 0
        st.session_state.selected_uid = None
        st.session_state.inbox_loaded_view_signature = None
        st.session_state.foreground_navigation_guard = True
        arm_foreground_interaction()
        st.rerun()

    # Refresh is queued from the button callback before this root run begins.
    # Keep the legacy action value as a compatibility fallback for any caller
    # that still supplies a direct boolean.  The durable request is intentionally
    # consumed only after the refresh attempt finishes, so an unexpected rerun
    # cannot silently turn the click into a stale no-op.
    refresh_requested = bool(
        st.session_state.get("inbox_refresh_requested", False)
        or inbox_actions.get("refresh", False)
    )

    if refresh_requested and st.session_state.get("mailbox_sync_in_progress"):
        # Automatic provider sync is already running off-thread. Do not start a
        # second competing provider traversal from the Refresh button. The
        # callback may already have painted the foreground loader, so clear it
        # here before returning to keep Refresh/Inbox clickable.
        st.session_state.inbox_refresh_requested = False
        st.session_state.loading = False
        clear_sidebar_activity(activity_slot)
        push_inbox_toast(
            "Mailbox synchronization is already running in the background.",
            "info",
            title="Mailbox updating",
            event_type="mailbox-sync-already-running",
            notify_bell=False,
        )
        return

    if refresh_requested:
        trace_action("inbox-refresh-process-start")
        # Claim the foreground lane *before* provider/network work. Previously
        # this guard was armed only after Refresh completed, so a timer fragment
        # could request a full rerun during the long provider traversal and leave
        # the browser on a stale/empty frame.
        arm_foreground_interaction()
        st.session_state.loading = True

        # Foreground mailbox refresh/new-mail discovery always outranks the
        # background old-mail catch-up and must not compete for provider/Ollama.
        _preempt_security_catchup_for_new_mail()

        refresh_progress = None
        refresh_finished_normally = False
        try:
            before_uids = st.session_state.email_store.get_active_uids(folder)
            unavailable_uids_before = st.session_state.email_store.get_unavailable_uids(folder)
            refresh_progress = start_sidebar_activity(
                activity_slot, "Checking for mailbox changes...", 0.08
            )
            update_sidebar_activity(
                refresh_progress, 0.30, "Fetching and updating the local inbox..."
            )
            fetch_result = _fetch_new_header_pages(folder, before_uids)
            reconciliation = (
                reconcile_folder(
                    st.session_state.imap_client,
                    st.session_state.email_store,
                    folder,
                )
                if fetch_result.get("success")
                else None
            )
            refresh_succeeded = bool(
                fetch_result.get("success")
                and reconciliation is not None
                and reconciliation.success
            )

            if refresh_succeeded:
                mark_provider_connection_ok()
                moved_to_inbox_uids = {
                    str(uid) for uid in reconciliation.moved_to_inbox_uids if str(uid)
                }
                moved_to_spam_uids = {
                    str(uid) for uid in reconciliation.moved_to_spam_uids if str(uid)
                }
                fetched_uids = {
                    str(uid) for uid in fetch_result.get("new_uids", set()) if str(uid)
                }
                transitions = _detect_cross_uid_location_transitions(
                    folder, fetched_uids, reconciliation.missing_uids
                )
                moved_to_inbox_uids.update(transitions.moved_to_inbox)
                moved_to_spam_uids.update(transitions.moved_to_spam)
                true_missing = set(reconciliation.missing_uids).difference(
                    transitions.consumed_missing_uids
                )
                apply_confirmed_deletions(true_missing)

                st.session_state.last_mail_reconcile = time.time()
                st.session_state.last_mail_check = time.time()
                update_sidebar_activity(refresh_progress, 0.84, "Reloading the inbox...")
                remote_total = int(
                    fetch_result.get("total")
                    or len(reconciliation.remote_uids)
                    or 0
                )
                st.session_state.email_store.update_remote_total(folder, remote_total)
                st.session_state.inbox_all_total = int(remote_total)

                after_uids = st.session_state.email_store.get_active_uids(folder)
                arrival_uids = after_uids.difference(before_uids)
                arrival_uids.difference_update(moved_to_inbox_uids)
                arrival_uids.difference_update(moved_to_spam_uids)
                restored_uids, new_uids = _classify_arrivals(
                    folder, arrival_uids, unavailable_uids_before
                )
                _notify_restored_emails(
                    st.session_state.email_store, folder, restored_uids
                )
                # Manual Refresh is still only the discovery mechanism; the move is
                # external/provider-driven, so it remains Bell-only. Record it before
                # any Security hydration/refinement can interrupt this refresh run.
                _notify_provider_location_moves(
                    st.session_state.email_store,
                    folder,
                    moved_to_inbox_uids,
                    moved_to_spam_uids,
                )

                _stage_auto_summary_arrivals(
                    new_uids, restored_uids, moved_to_inbox_uids
                )
                _drop_auto_summary_uids(moved_to_spam_uids)

                if new_uids:
                    pending_notifications = {
                        str(uid)
                        for uid in st.session_state.get("pending_new_mail_notification_uids", set())
                        if str(uid)
                    }
                    pending_notifications.update(new_uids)
                    st.session_state.pending_new_mail_notification_uids = pending_notifications
                    _register_new_mail_notification_cycle(new_uids)

                st.session_state.clear_checked_after_refresh = list(
                    st.session_state.checked_uids
                )
                st.session_state.new_mail_count = 0
                st.session_state.inbox_loaded_view_signature = None

                # Mailbox fetch/reconcile may use the foreground loader, but genuinely
                # NEW-mail Security must not. NEW rows are already staged ui_visible=0,
                # so dismiss the blocking overlay before Security hydration/refinement
                # and keep the workspace usable while the contextual worker finishes.
                # Initial first-sync/catch-up Security in app.py intentionally retains
                # its dedicated blocking login experience.
                if new_uids:
                    finish_sidebar_activity(refresh_progress, "New mail found")
                    clear_sidebar_activity(activity_slot)
                    refresh_progress = None
                else:
                    update_sidebar_activity(
                        refresh_progress, 0.92, "Finalizing mailbox changes..."
                    )

                refresh_security_uids = (
                    set(new_uids)
                    .union(restored_uids)
                    .union(moved_to_inbox_uids)
                    .union(moved_to_spam_uids)
                )
                newly_incomplete = _incomplete_security_uids(folder, refresh_security_uids)
                _hydrate_security_for_uids(folder, refresh_security_uids)

                # Match automatic polling: restored/moved legacy risk candidates can
                # finish their targeted refinement synchronously, but genuinely NEW
                # mail gets the contextual second opinion in the dedicated worker.
                # NEW rows stay ui_visible=0 until that worker publishes the final
                # Security verdict, so the refresh button returns without waiting on
                # the local LLM and unsafe mail can never flash in Inbox first.
                synchronous_uids = newly_incomplete.difference(new_uids)
                _refine_security_for_uids(folder, synchronous_uids)
                background_uids = _start_new_mail_security_refinement(folder, new_uids)

                store = st.session_state.get("email_store")
                publish_now_uids = refresh_security_uids.difference(background_uids)
                published_uids = (
                    store.publish_security_ready(folder, publish_now_uids)
                    if store is not None else set()
                )
                _release_published_new_mail(folder, published_uids)
                _hydrate_staged_auto_individual_security(folder)
                _publish_provider_move_state_after_security(
                    folder, moved_to_inbox_uids, moved_to_spam_uids
                )
                if not background_uids:
                    _queue_staged_auto_individual_after_security(folder)
                finish_sidebar_activity(refresh_progress, "Mailbox check complete")
            else:
                error = (
                    fetch_result.get("error")
                    if not fetch_result.get("success")
                    else getattr(reconciliation, "error", "Unknown refresh error")
                )
                mark_provider_connection_issue(error)
                push_inbox_toast(
                    provider_error_message(error, action="refresh"),
                    "error",
                    title="Synchronization failed",
                    event_type="manual-mailbox-sync-failed",
                    notify_bell=False,
                )

            # Preserve the existing Refresh behavior (return to the default first
            # page/filter) but commit that reset only after the provider attempt
            # has reached a normal endpoint. A half-interrupted refresh can no
            # longer reset the list to 0 while old cards remain in the browser.
            refresh_finished_normally = True
        except Exception as error:
            mark_provider_connection_issue(error)
            push_inbox_toast(
                provider_error_message(error, action="refresh"),
                "error",
                title="Synchronization failed",
                event_type="manual-mailbox-sync-failed",
                notify_bell=False,
            )
            print(f"[mail-refresh] Refresh failed safely: {error}", flush=True)
        finally:
            st.session_state.inbox_refresh_requested = False
            if refresh_finished_normally:
                st.session_state.inbox_refresh_reset_pending = True
            st.session_state.loading = False
            clear_sidebar_activity(activity_slot)
            # Keep background fragments out until the post-refresh root render is
            # completely painted, then app.py releases the one-render guard.
            st.session_state.foreground_navigation_guard = True
            arm_foreground_interaction()

        st.rerun()

    if inbox_actions["next"]:
        # Pagination reads the next local/cached page directly. Keep this path
        # free of the blocking app loader so fast page changes do not flash a
        # second overlay behind the workspace. Search/refresh/sync loaders are
        # intentionally unchanged.
        st.session_state.selected_uid = None
        if st.session_state.search_active:
            page_size = MAX_EMAILS_FETCH
            st.session_state.inbox_search_page_size = page_size
            next_offset = (
                max(0, int(st.session_state.get("inbox_search_offset", 0)))
                + page_size
            )
            load_local_page(
                next_offset,
                folder,
                search_mode=True,
                query=st.session_state.get("inbox_search_query", ""),
            )
        else:
            next_offset = st.session_state.inbox_offset + MAX_EMAILS_FETCH
            load_local_page(next_offset, folder)
        st.session_state.foreground_navigation_guard = True
        arm_foreground_interaction()
        st.rerun()

    if inbox_actions["prev"]:
        # Same non-blocking local pagination rule as Next.
        st.session_state.selected_uid = None
        if st.session_state.search_active:
            page_size = MAX_EMAILS_FETCH
            st.session_state.inbox_search_page_size = page_size
            previous_offset = max(
                0,
                int(st.session_state.get("inbox_search_offset", 0)) - page_size,
            )
            load_local_page(
                previous_offset,
                folder,
                search_mode=True,
                query=st.session_state.get("inbox_search_query", ""),
            )
        else:
            previous_offset = max(
                0, st.session_state.inbox_offset - MAX_EMAILS_FETCH
            )
            load_local_page(previous_offset, folder)
        st.session_state.foreground_navigation_guard = True
        arm_foreground_interaction()
        st.rerun()
