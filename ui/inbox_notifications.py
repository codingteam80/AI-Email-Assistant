# Inbox and AI-summary notifications.
#
# Informational mailbox and summary events use Streamlit's native top-right toast
# overlay so they never reflow or block the workspace. Summary flows that require
# a user decision use a native ``st.dialog`` styled to match the To-Do confirmation
# system.
from __future__ import annotations

import hashlib
import html
from datetime import datetime

import streamlit as st

from config import UI_FOREGROUND_SETTLE_SECONDS

from ui.notification_center import record_notification
from services.ui_interaction_service import arm_foreground_interaction


def _toast_id(message: str, queue_size: int) -> str:
    raw = f"{message}-{datetime.now().isoformat(timespec='microseconds')}-{queue_size}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:14]


def push_inbox_toast(
    message: str,
    kind: str = "info",
    on_dismiss: str | None = None,
    *,
    title: str | None = None,
    details: list[str] | tuple[str, ...] | None = None,
    event_type: str = "",
    entity_id: str = "",
    notify_bell: bool = True,
) -> None:
    # Queue one mailbox notification.
    #
    # ``on_dismiss`` is kept for backwards compatibility with older saved state,
    # but new summary decisions no longer use close-to-continue behavior.
    clean_message = str(message or "").strip()
    if not clean_message:
        return

    queue = list(st.session_state.get("inbox_toasts", []))
    queue.append(
        {
            "id": _toast_id(clean_message, len(queue)),
            "message": clean_message,
            "kind": str(kind or "info").strip().casefold(),
            "title": str(title or "").strip(),
            "on_dismiss": str(on_dismiss or "").strip(),
        }
    )
    st.session_state.inbox_toasts = queue[-5:]
    if notify_bell:
        record_notification(
            title=title or _inbox_toast_title(str(kind or "info").strip().casefold()),
            message=clean_message,
            kind=kind,
            workspace="inbox",
            details=details,
            event_type=event_type or str(kind or "info").strip().casefold(),
            entity_id=entity_id,
        )


def push_summary_toast(
    message: str,
    kind: str = "info",
    *,
    title: str | None = None,
    details: list[str] | tuple[str, ...] | None = None,
    event_type: str = "",
    entity_id: str = "",
    notify_bell: bool = False,
) -> None:
    # Queue one non-blocking AI-summary notification.
    #
    # Like the To-Do toast system, the newest notification wins. It is rendered
    # with ``st.toast`` in Streamlit's overlay layer and therefore cannot push or
    # resize Inbox / AI Summary / To-Do containers.
    clean_message = str(message or "").strip()
    if not clean_message:
        return
    st.session_state.summary_toasts = [
        {
            "id": _toast_id(clean_message, 0),
            "message": clean_message,
            "kind": str(kind or "info").strip().casefold(),
            "title": str(title or "").strip(),
        }
    ]
    normalized_kind = str(kind or "info").strip().casefold()
    if notify_bell:
        record_notification(
            title=title or _summary_toast_title(clean_message, normalized_kind),
            message=clean_message,
            kind=normalized_kind,
            workspace="summary",
            details=details,
            event_type=event_type or "summary",
            entity_id=entity_id,
        )


def _summary_toast_title(message: str, kind: str) -> str:
    normalized = str(message or "").strip().casefold()
    if normalized.startswith("auto summary created"):
        return "Auto Summary created"
    if normalized.startswith("batch summary:"):
        return "Batch Summary queued"
    if normalized.startswith("select at least 2 emails"):
        return "Batch Summary needs 2 emails"
    if normalized.startswith("batch summary fallback") or normalized.startswith("only 1 new email"):
        return "Batch Summary fallback"
    if "already summarized" in normalized:
        return "Already summarized"
    if normalized.startswith("auto summary stopped"):
        return "Auto Summary stopped"
    if normalized.startswith("auto summary could not"):
        return "Auto Summary issue"
    if normalized.startswith("generated one batch summary"):
        return "Batch Summary created"
    if normalized.startswith("generated "):
        return "Summary created"
    if normalized.startswith("summary generation stopped"):
        return "Summary generation stopped"
    if normalized.startswith("could not summarize"):
        return "Summary issue"
    if normalized.startswith("reply sent"):
        return "Reply sent"
    if kind == "success":
        return "Summary created"
    if kind == "error":
        return "Summary failed"
    if kind == "warning":
        return "Summary notice"
    return "Summary notification"


def render_summary_toasts() -> None:
    # Render the newest summary notice as a top-right native Streamlit toast.
    toasts = list(st.session_state.get("summary_toasts", []))
    if not toasts:
        return

    toast = toasts[-1]
    message = str(toast.get("message") or "").strip()
    kind = str(toast.get("kind") or "info").strip().casefold()
    title = str(toast.get("title") or "").strip() or _summary_toast_title(message, kind)

    if kind == "success":
        icon = ":material/check_circle:"
    elif kind == "error":
        icon = ":material/error:"
    elif kind in {"warning", "waiting"}:
        icon = ":material/schedule:"
    else:
        icon = ":material/info:"

    # Consume before rendering so unrelated future reruns never replay it.
    st.session_state.summary_toasts = []
    st.toast(
        f"**{title}**  \n{message}",
        icon=icon,
        duration="short",
    )


def queue_summary_confirmation(*, selected_count: int, ready_count: int, skipped_count: int) -> None:
    # Open the mixed-selection confirmation on the next app rerun.
    st.session_state.summary_pending_confirmation = {
        "selected_count": max(0, int(selected_count or 0)),
        "ready_count": max(0, int(ready_count or 0)),
        "skipped_count": max(0, int(skipped_count or 0)),
    }


def _dismiss_summary_confirmation() -> None:
    # Treat the dialog X/backdrop as Cancel, never as implicit approval.
    st.session_state.pop("summary_pending_confirmation", None)
    st.session_state.pop("deferred_summary_request", None)
    st.session_state.summary_deferred_ready = False


def _summary_count_label(count: int, singular: str, plural: str | None = None) -> str:
    noun = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {noun}"


@st.dialog(
    "Summary confirmation",
    width="medium",
    dismissible=False,
)
def _show_summary_confirmation_dialog() -> None:
    pending = st.session_state.get("summary_pending_confirmation") or {}
    request = st.session_state.get("deferred_summary_request") or {}
    if not pending or not request:
        # A dialog is fragment-scoped in Streamlit. If its state was cleared
        # by a widget inside the dialog, returning here would leave the outer
        # dialog shell visible but empty. Force a full-app rerun so the dialog
        # is no longer mounted at all.
        _dismiss_summary_confirmation()
        arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
        st.rerun(scope="app")

    selected_count = int(pending.get("selected_count") or 0)
    ready_count = int(pending.get("ready_count") or 0)
    skipped_count = int(pending.get("skipped_count") or 0)

    selected_label = _summary_count_label(selected_count, "selected email")
    ready_label = _summary_count_label(ready_count, "email")
    skipped_label = _summary_count_label(skipped_count, "email")

    st.markdown(
        f"""
        <div class="todo-confirm-shell is-summary summary-confirm-shell">
            <div class="todo-confirm-header">
                <div class="todo-confirm-icon summary-confirm-icon" aria-hidden="true">✦</div>
                <div class="todo-confirm-heading-copy">
                    <div class="todo-confirm-title">Continue with unsummarized emails?</div>
                    <div class="todo-confirm-subtitle">Some selected emails already have AI summaries.</div>
                </div>
            </div>
            <div class="todo-confirm-transition summary-confirm-transition">
                <span class="todo-confirm-status-pill summary-pill-selected">{html.escape(selected_label)}</span>
                <span class="todo-confirm-arrow" aria-hidden="true">→</span>
                <span class="todo-confirm-status-pill summary-pill-ready">Generate {html.escape(ready_label)}</span>
            </div>
            <div class="todo-confirm-description">
                Existing summaries will be kept. Only emails without a summary will be processed.
            </div>
            <div class="todo-confirm-info summary-confirm-info">
                <span class="todo-confirm-info-icon" aria-hidden="true">i</span>
                <div class="todo-confirm-info-copy">
                    <div><strong>{html.escape(skipped_label)}</strong> already summarized and will be skipped.</div>
                    <div class="todo-confirm-deadline-line">The manual summary job starts only after you choose Continue Summary.</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cancel_col, continue_col = st.columns(2, gap="small")
    with cancel_col:
        if st.button(
            "Cancel",
            key="summary_mixed_selection_cancel",
            use_container_width=True,
        ):
            _dismiss_summary_confirmation()
            arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
            st.rerun(scope="app")

    with continue_col:
        if st.button(
            "Continue Summary",
            key="summary_mixed_selection_confirm",
            type="primary",
            use_container_width=True,
        ):
            st.session_state.pop("summary_pending_confirmation", None)
            st.session_state.summary_deferred_ready = True
            arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
            st.rerun(scope="app")


def render_summary_confirmation() -> None:
    # Render a blocking confirmation only when a summary decision is pending.
    if st.session_state.get("summary_pending_confirmation"):
        _show_summary_confirmation_dialog()


def dismiss_inbox_toast(toast_id: str) -> None:
    # Remove one queued mailbox notification by ID.
    st.session_state.inbox_toasts = [
        item
        for item in st.session_state.get("inbox_toasts", [])
        if str(item.get("id") or "") != str(toast_id or "")
    ]


def _inbox_toast_title(kind: str) -> str:
    if kind == "new-mail":
        return "New email"
    if kind == "deleted":
        return "Inbox updated"
    if kind == "restored":
        return "Email restored"
    if kind == "security":
        return "Security alert"
    if kind == "error":
        return "Inbox issue"
    if kind == "warning":
        return "Inbox notice"
    return "Inbox notification"


def render_inbox_toasts() -> None:
    # Render queued mailbox events as native top-right overlays.
    #
    # Consume the whole queue first so simultaneous receive/delete reconciliation
    # cannot strand a second notification until an unrelated future rerun. Native
    # Streamlit toasts stack in the overlay layer without moving page content.
    toasts = list(st.session_state.get("inbox_toasts", []))
    if not toasts:
        return
    st.session_state.inbox_toasts = []

    for current in toasts:
        message = str(current.get("message") or "").strip()
        kind = str(current.get("kind") or "info").strip().casefold()
        title = str(current.get("title") or "").strip() or _inbox_toast_title(kind)
        if not message:
            continue

        if kind == "new-mail":
            icon = ":material/mail:"
        elif kind == "deleted":
            icon = ":material/delete:"
        elif kind == "restored":
            icon = ":material/restore:"
        elif kind == "security":
            icon = ":material/security:"
        elif kind == "error":
            icon = ":material/error:"
        elif kind in {"warning", "waiting"}:
            icon = ":material/info:"
        else:
            icon = ":material/info:"

        st.toast(
            f"**{title}**  \n{message}",
            icon=icon,
            duration="short",
        )
