# Background preparation for AI reply drafts with the shared app loader.
from concurrent.futures import CancelledError, ThreadPoolExecutor
import time

import streamlit as st

from config import DRAFT_GENERATION_FRAGMENT_SECONDS

from services.white_stale_trace_service import trace_action

from services.ai_service import draft_reply, reply_draft_block_reason
from services.ollama_runtime_service import user_facing_ai_error
from services.generation_trace_service import (
    begin_generation_trace, finish_generation_trace, new_generation_job_id,
    trace_event, trace_external, trace_launch,
)
from services.thread_service import build_thread_email
from services.ui_interaction_service import foreground_interaction_is_settling
from storage.session_store import save_reply_draft
from storage.summary_store import SUMMARY_FOLDER
from ui.inbox_notifications import push_summary_toast
from services.reply_draft_state_service import reply_draft_state_fingerprint
from ui.loading import (
    clear_app_loading_state,
    set_app_loading_state,
    update_app_loading_state,
)


def _build_reply_draft(
    summary: dict,
    original_email: dict | None,
    client=None,
    store=None,
    trace_job_id: str = "",
) -> str:
    # Reconstruct the provider-backed conversation in the worker when possible.
    # This keeps stale quoted history from becoming the source of truth and lets
    # Outlook include Sent Items through its conversation expansion path.
    begin_generation_trace("DRAFT", trace_job_id, mode="reply")
    try:
        source = dict(original_email or {}) if original_email else None
        rebuild_started = time.perf_counter()
        thread_mode = "local"
        if source and client is not None and store is not None:
            folder = str(source.get("folder") or SUMMARY_FOLDER)
            try:
                source = build_thread_email(client, store, source, folder)
                thread_mode = "provider_rebuild"
            except (ConnectionError, OSError, RuntimeError, ValueError):
                # Reply generation can still use the locally stored source when the
                # provider cannot expand the conversation at this moment.
                source = dict(original_email or {})
                thread_mode = "local_fallback"
        trace_event(
            "thread_ready",
            elapsed=time.perf_counter() - rebuild_started,
            thread_mode=thread_mode,
            items=int((source or {}).get("thread_count") or 1) if source else 0,
        )
        result = draft_reply(dict(summary or {}), source)
        finish_generation_trace("ok")
        return result
    except Exception:
        finish_generation_trace("error")
        raise


def _connected_account_identity(client=None) -> tuple[str, str, str]:
    # Reuse the provider-neutral account identity shown by the sidebar. Outlook
    # exposes a real displayName through the cached Graph profile. IMAP/Gmail may
    # not expose one, so only the footer uses the mailbox local-part fallback;
    # ownership still receives the address without pretending the local-part is
    # a verified person's name.
    account_email = str(
        st.session_state.get("active_store_account")
        or st.session_state.get("email_address")
        or getattr(client, "email_address", "")
        or ""
    ).strip()
    display_name = str(st.session_state.get("profile_display_name") or "").strip()

    if not display_name and client is not None:
        profile = getattr(client, "_profile", None)
        if isinstance(profile, dict):
            display_name = str(profile.get("displayName") or "").strip()

    signature_name = display_name
    if not signature_name and account_email:
        signature_name = account_email.split("@", 1)[0].strip()

    return display_name, signature_name, account_email


def start_draft_generation(summary: dict, original_email: dict | None = None) -> bool:
    # Start one reply-draft job and switch on the shared blocking overlay.
    if st.session_state.get("draft_processing"):
        return False

    uid = str((summary or {}).get("uid") or "")
    if not uid:
        st.session_state.draft_prepare_error_uid = ""
        st.session_state.draft_prepare_error = ""
        push_summary_toast(
            "This summary cannot be used to prepare a draft.",
            "warning",
            title="Draft unavailable",
            event_type="reply-draft-unavailable",
            notify_bell=False,
        )
        return False

    block_reason = reply_draft_block_reason(summary or {}, original_email)
    if block_reason:
        st.session_state.draft_prepare_error_uid = ""
        st.session_state.draft_prepare_error = ""
        push_summary_toast(
            block_reason,
            "warning",
            title="Draft unavailable",
            event_type="reply-draft-unavailable",
            entity_id=uid,
            notify_bell=False,
        )
        return False

    client = st.session_state.get("imap_client")
    store = st.session_state.get("email_store")
    prepared_summary = dict(summary or {})
    state_fingerprint = reply_draft_state_fingerprint(prepared_summary)
    display_name, signature_name, account_email = _connected_account_identity(client)
    if account_email or display_name:
        prepared_summary["reply_author_identity"] = (
            f"{display_name} <{account_email}>"
            if display_name and account_email
            else account_email or display_name
        )
    if signature_name:
        # The final footer always comes from the connected account identity, not
        # from model-generated aliases or the [Your name] placeholder.
        prepared_summary["user_signature"] = signature_name

    trace_job_id = new_generation_job_id("draft")
    trace_launch("DRAFT", trace_job_id, mode="reply", items=1)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="email-draft")
    future = executor.submit(
        _build_reply_draft, prepared_summary, original_email, client, store, trace_job_id
    )

    st.session_state.draft_executor = executor
    st.session_state.draft_future = future
    st.session_state.draft_processing = True
    st.session_state.draft_processing_uid = uid
    st.session_state.draft_trace_job_id = trace_job_id
    st.session_state.draft_processing_state_fingerprint = state_fingerprint
    st.session_state.draft_cancel_requested = False
    st.session_state.draft_prepare_error_uid = ""
    st.session_state.draft_prepare_error = ""
    set_app_loading_state(
        title="Please wait...",
        subtitle="Preparing your draft email...",
        detail="",
    )
    return True


def request_draft_cancellation() -> bool:
    trace_action("draft-cancel-request")
    # A running Ollama request cannot be force-killed safely from Streamlit.
    # Mark it cancelled, try to cancel it before it starts, and otherwise wait
    # for the in-flight step to end before discarding the result without saving.
    if not st.session_state.get("draft_processing"):
        return False
    if st.session_state.get("draft_cancel_requested"):
        return True

    st.session_state.draft_cancel_requested = True
    future = st.session_state.get("draft_future")
    if future is not None and not future.done():
        future.cancel()
    update_app_loading_state(
        title="Cancelling draft...",
        subtitle="Finishing the current step safely...",
        detail="",
    )
    return True


def poll_draft_generation() -> bool:
    # Commit a completed reply draft on the Streamlit UI thread. A cancellation
    # that arrives before this commit always wins and the generated text is
    # discarded, matching the late-cancel protection used by Summary generation.
    future = st.session_state.get("draft_future")
    if not st.session_state.get("draft_processing") or future is None:
        return False
    if not future.done():
        return False

    uid = str(st.session_state.get("draft_processing_uid") or "")
    trace_job_id = str(st.session_state.get("draft_trace_job_id") or "")
    trace_external("DRAFT", trace_job_id, "future_ready")
    cancel_requested = bool(st.session_state.get("draft_cancel_requested"))
    state_fingerprint = str(st.session_state.get("draft_processing_state_fingerprint") or "")
    st.session_state.draft_processing = False
    clear_app_loading_state()

    try:
        prepared_draft = future.result()
        if cancel_requested:
            st.session_state.draft_prepare_error_uid = ""
            st.session_state.draft_prepare_error = ""
            if str(st.session_state.get("draft_dialog_uid") or "") == uid:
                st.session_state.pop("draft_dialog_uid", None)
            if str(st.session_state.get("draft_dialog_pending_uid") or "") == uid:
                st.session_state.pop("draft_dialog_pending_uid", None)
            push_summary_toast(
                "Draft generation cancelled.",
                "info",
                event_type="reply-draft-cancelled",
                entity_id=uid,
            )
            trace_external("DRAFT", trace_job_id, "commit_done", status="cancelled")
            return True

        session_token = str(st.session_state.get("session_token") or "")
        if not save_reply_draft(session_token, uid, prepared_draft, state_fingerprint):
            raise RuntimeError("The authenticated session could not store the draft.")
        st.session_state.draft_prepare_error_uid = ""
        st.session_state.draft_prepare_error = ""
        # Open the finished draft automatically in the current workspace on
        # the full-app rerun triggered by the monitor below. Use a new editor
        # instance so no stale text-area state can be reused.
        instance_key = f"standalone_reply_editor_instance_{uid}"
        st.session_state[instance_key] = int(st.session_state.get(instance_key, 0) or 0) + 1
        # Queue the dialog handoff. The next full-app run promotes this UID
        # before rendering, so st.dialog is opened by the stable app root rather
        # than from this timer-driven background fragment.
        st.session_state.draft_dialog_pending_uid = uid
        push_summary_toast(
            "Draft generated successfully.",
            "success",
            title="Draft ready",
            event_type="reply-draft-created",
            entity_id=uid,
        )
        trace_external("DRAFT", trace_job_id, "commit_done", status="ok")
    except CancelledError:
        # Future.cancel() succeeds only when the worker has not started yet.
        # Treat that as a normal user cancellation, never as a draft error.
        st.session_state.draft_prepare_error_uid = ""
        st.session_state.draft_prepare_error = ""
        if str(st.session_state.get("draft_dialog_pending_uid") or "") == uid:
            st.session_state.pop("draft_dialog_pending_uid", None)
        push_summary_toast(
            "Draft generation cancelled.",
            "info",
            event_type="reply-draft-cancelled",
            entity_id=uid,
        )
    except Exception as error:
        if cancel_requested:
            st.session_state.draft_prepare_error_uid = ""
            st.session_state.draft_prepare_error = ""
            push_summary_toast(
                "Draft generation cancelled.",
                "info",
                event_type="reply-draft-cancelled",
                entity_id=uid,
            )
        else:
            safe_error = user_facing_ai_error(error, action="draft")
            print(f"[draft] Generation failed: {error}", flush=True)
            st.session_state.draft_prepare_error_uid = ""
            st.session_state.draft_prepare_error = ""
            push_summary_toast(
                safe_error,
                "error",
                title="AI unavailable" if "AI is currently unavailable" in safe_error else "Draft failed",
                event_type="reply-draft-failed",
                entity_id=uid,
                notify_bell=False,
            )
        if str(st.session_state.get("draft_dialog_uid") or "") == uid:
            st.session_state.pop("draft_dialog_uid", None)
        if str(st.session_state.get("draft_dialog_pending_uid") or "") == uid:
            st.session_state.pop("draft_dialog_pending_uid", None)
    finally:
        executor = st.session_state.pop("draft_executor", None)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        st.session_state.pop("draft_future", None)
        st.session_state.draft_processing_uid = ""
        st.session_state.draft_cancel_requested = False
        st.session_state.pop("draft_trace_job_id", None)
        st.session_state.pop("draft_processing_state_fingerprint", None)

    return True


def render_draft_cancel_control() -> None:
    # Keep the Cancel control on the stable app root. Use an on_click callback
    # so cancellation state is applied before Streamlit rebuilds the page.
    # Calling st.rerun() from inside the already-triggered button rerun caused
    # a second full-app rerun and briefly unmounted the loading overlay.
    if not st.session_state.get("draft_processing"):
        return

    cancel_requested = bool(st.session_state.get("draft_cancel_requested"))
    with st.container(key="draft_cancel_overlay"):
        if cancel_requested:
            st.button(
                "Cancelling...",
                key="draft_cancel_button",
                disabled=True,
                use_container_width=True,
            )
        else:
            st.button(
                "Cancel",
                key="draft_cancel_button",
                type="secondary",
                use_container_width=True,
                on_click=request_draft_cancellation,
            )


@st.fragment(run_every=DRAFT_GENERATION_FRAGMENT_SECONDS)
def monitor_draft_generation(activity_slot=None) -> None:
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return
    # Poll only. The loading overlay and Cancel button are root-owned so the
    # timer can never remount them every half second while Ollama is drafting.
    if not st.session_state.get("draft_processing"):
        return

    if poll_draft_generation():
        st.rerun(scope="app")
