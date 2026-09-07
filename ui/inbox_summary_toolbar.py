# Compact Inbox status strip for manual and automatic summary state.
import html
import time

import streamlit as st


def render_inbox_summary_toolbar(spam_view: bool = False, folder: str = "INBOX") -> None:
    # Render the workspace title and Inbox-only summary state chips.
    if spam_view:
        st.markdown(
            '<div class="mailmind-workspace-header">'
            '<div class="mailmind-workspace-title">Spam</div>'
            '<div class="mailmind-workspace-controls mailmind-workspace-controls-empty"></div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    auto_enabled = bool(st.session_state.get("auto_summary_enabled"))
    auto_type = str(st.session_state.get("auto_summary_type_choice") or "Individual")
    auto_origin = str(st.session_state.get("summary_job_origin") or "manual")
    auto_processing = bool(st.session_state.get("summary_processing") and auto_origin == "auto")
    pending = {str(uid) for uid in st.session_state.get("pending_auto_summary_uids", set()) if str(uid)}

    activity_markup = ""
    if auto_enabled and auto_processing:
        job_count = len(st.session_state.get("summary_job_uids", []) or [])
        item_word = "email" if job_count == 1 else "emails"
        activity_markup = (
            '<div class="inbox-summary-display-chip queue-chip is-processing">'
            '<span class="inbox-summary-queue-icon">↻</span>'
            f'{html.escape(auto_type)}: Summarizing {job_count} {item_word}…'
            '</div>'
        )
    elif auto_enabled and pending:
        count = len(pending)
        item_word = "email" if count == 1 else "emails"
        if auto_type == "Batch":
            deadline = float(st.session_state.get("auto_summary_batch_deadline", 0.0) or 0.0)
            remaining = max(0, int(round(deadline - time.time()))) if deadline else 0
            wait_text = f"waiting {remaining}s" if remaining > 0 else "starting…"
            activity = f"Batch: {count} {item_word} queued • {wait_text}"
        else:
            activity = f"Individual: {count} {item_word} queued"
        activity_markup = (
            '<div class="inbox-summary-display-chip queue-chip is-waiting">'
            '<span class="inbox-summary-queue-icon">◷</span>'
            f'{html.escape(activity)}'
            '</div>'
        )

    controls_class = (
        "mailmind-workspace-controls"
        if activity_markup
        else "mailmind-workspace-controls mailmind-workspace-controls-empty"
    )
    header_markup = (
        '<div class="mailmind-workspace-header">'
        '<div class="mailmind-workspace-title">Inbox</div>'
        f'<div class="{controls_class}">'
        f'{activity_markup}'
        '</div>'
        '</div>'
    )
    st.markdown(header_markup, unsafe_allow_html=True)
