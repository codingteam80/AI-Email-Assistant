"""Reply Draft cache invalidation tied to Summary/To-Do current state."""
from __future__ import annotations

import streamlit as st

from storage.session_store import delete_reply_draft


def invalidate_reply_draft(uid: str) -> None:
    """Remove a prepared reply and all editor caches for one source email UID."""
    uid = str(uid or "").strip()
    if not uid:
        return

    session_token = str(st.session_state.get("session_token") or "")
    delete_reply_draft(session_token, uid)

    for key in (
        f"standalone_reply_draft_{uid}",
        f"standalone_reply_backup_{uid}",
        f"standalone_reply_sent_{uid}",
        f"standalone_reply_attachments_{uid}",
        f"standalone_reply_confirm_send_{uid}",
        f"standalone_reply_send_error_{uid}",
    ):
        st.session_state.pop(key, None)

    editor_prefix = f"standalone_reply_editor_{uid}_"
    for key in list(st.session_state.keys()):
        if str(key).startswith(editor_prefix):
            st.session_state.pop(key, None)

    if str(st.session_state.get("draft_dialog_uid") or "") == uid:
        st.session_state.pop("draft_dialog_uid", None)
    if str(st.session_state.get("draft_dialog_pending_uid") or "") == uid:
        st.session_state.pop("draft_dialog_pending_uid", None)

    # A regenerated draft must get a fresh Streamlit text-area identity.
    instance_key = f"standalone_reply_editor_instance_{uid}"
    st.session_state[instance_key] = int(st.session_state.get(instance_key, 0) or 0) + 1


def invalidate_updated_summary_drafts(summary: dict) -> None:
    """Invalidate drafts only for thread/source records whose current state changed."""
    if not isinstance(summary, dict):
        return

    is_batch = str(summary.get("record_type") or "").strip().casefold() == "batch"
    if is_batch:
        # Batch Reply Draft actions belong to each source email. The summary
        # worker supplies a temporary list of source UIDs changed in this job;
        # remove it before persistence so a later unrelated run cannot re-fire it.
        updated_uids = [
            str(value or "").strip()
            for value in (summary.pop("_reply_draft_updated_uids", []) or [])
            if str(value or "").strip()
        ]
        for uid in dict.fromkeys(updated_uids):
            invalidate_reply_draft(uid)
        return

    if bool(summary.get("_thread_summary_updated")):
        invalidate_reply_draft(str(summary.get("uid") or ""))
