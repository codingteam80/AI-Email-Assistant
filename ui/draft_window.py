# AI reply editor used in the in-app Draft email dialog.
import hashlib
import html
from email.utils import parseaddr

import streamlit as st

from config import DRAFT_EDITOR_HEIGHT, UI_FOREGROUND_SETTLE_SECONDS

from services.white_stale_trace_service import trace_action

from services.send_service import send_reply
from services.attachment_policy_service import classify_attachment
from services.ui_interaction_service import arm_foreground_interaction
from services.network_status_service import (
    is_network_error,
    mark_provider_connection_issue,
    mark_provider_connection_ok,
    provider_error_message,
)
from storage.session_store import (
    delete_reply_draft,
    delete_reply_draft_attachments,
    get_reply_draft,
    get_reply_draft_attachments,
    save_reply_draft,
    save_reply_draft_attachments,
)
from ui.reader import _collapsible_cc_html, _collapsible_to_html
from ui.inbox_notifications import push_summary_toast


def _foreground_rerun(*, scope: str | None = None) -> None:
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
    if scope is None:
        st.rerun()
        return
    st.rerun(scope=scope)


def _outbound_body(formatted_draft: str) -> str:
    # Remove the display-only To line before sending the actual message body.
    lines = str(formatted_draft or "").splitlines()
    if lines and lines[0].strip().casefold().startswith("to:"):
        lines = lines[1:]
    return "\n".join(lines).strip()


def _persist_current_dialog_draft(uid: str | None = None) -> None:
    # Persist the latest non-empty draft without letting modal reruns erase it.
    current_uid = str(uid or st.session_state.get("draft_dialog_uid") or "").strip()
    if not current_uid:
        return

    session_token = str(st.session_state.get("session_token") or "")
    if not session_token:
        return

    draft_key = f"standalone_reply_draft_{current_uid}"
    backup_key = f"standalone_reply_backup_{current_uid}"
    instance_key = f"standalone_reply_editor_instance_{current_uid}"
    editor_instance = int(st.session_state.get(instance_key, 1) or 1)
    editor_key = f"standalone_reply_editor_{current_uid}_{editor_instance}"

    editor_text = str(st.session_state.get(editor_key, ""))
    cached_text = str(st.session_state.get(draft_key, ""))
    backup_text = str(st.session_state.get(backup_key, ""))
    saved_text = get_reply_draft(session_token, current_uid)

    # Button clicks/dialog transitions can briefly clear the Streamlit widget
    # state. Never treat that transient blank as an intentional draft deletion.
    if editor_text.strip():
        current_text = editor_text
    elif cached_text.strip():
        current_text = cached_text
    elif backup_text.strip():
        current_text = backup_text
    elif saved_text.strip():
        current_text = saved_text
    else:
        return

    # Do not write back to editor_key here. This helper can run after the
    # text_area widget has already been instantiated, and Streamlit forbids
    # mutating a widget-owned session_state key at that point.
    st.session_state[draft_key] = current_text
    st.session_state[backup_key] = current_text
    save_reply_draft(session_token, current_uid, current_text)


def _persist_editor_change(uid: str, draft_key: str, editor_key: str, backup_key: str) -> None:
    trace_action("draft-editor-change", text_len=len(str(st.session_state.get(editor_key, "") or "")))
    # Persist only non-empty edits; never let a modal transition erase a draft.
    session_token = str(st.session_state.get("session_token") or "")
    if not session_token:
        return

    current_text = str(st.session_state.get(editor_key, ""))
    if not current_text.strip():
        return

    # Keep two independent non-widget copies. Streamlit may remove the widget
    # key when a dialog closes, but these keys survive the rerun.
    st.session_state[draft_key] = current_text
    st.session_state[backup_key] = current_text
    save_reply_draft(session_token, uid, current_text)


def _clear_draft_dialog_state() -> None:
    # Forget the pending modal so a dismissed dialog stays closed.
    _persist_current_dialog_draft()
    uid = str(st.session_state.get("draft_dialog_uid") or "").strip()
    if uid:
        st.session_state.pop(f"standalone_reply_confirm_send_{uid}", None)
    st.session_state.pop("draft_dialog_uid", None)


def _find_summary(uid: str, folder: str) -> dict | None:
    summaries = st.session_state.summary_store.load_all(folder)
    summary = next(
        (item for item in summaries if str(item.get("uid", "")) == uid),
        None,
    )
    if summary is not None:
        return summary

    # Batch source emails live inside email_breakdowns instead of as
    # standalone summary cards. Resolve them for Draft email actions.
    return next(
        (
            source
            for item in summaries
            for source in (item.get("email_breakdowns") or [])
            if str(source.get("uid", "")) == uid
        ),
        None,
    )


def _reply_subject(subject: str) -> str:
    value = str(subject or "").strip() or "(No Subject)"
    return value if value.casefold().startswith("re:") else f"Re: {value}"


def _source_metadata(summary: dict, uid: str, folder: str) -> dict:
    # Prefer cached source headers for recipient metadata when available.
    source = {}
    store = st.session_state.get("email_store")
    if store is not None:
        try:
            source = store.get_email(folder, uid) or {}
        except Exception:
            source = {}
    return {
        "subject": source.get("subject") or summary.get("subject") or "(No Subject)",
        "from": source.get("from") or summary.get("from") or "Unknown sender",
        "to": source.get("to") or summary.get("to") or st.session_state.get("email_address") or "Current user",
        "cc": source.get("cc") or summary.get("cc") or "",
    }


def _meta_icon(kind: str) -> str:
    paths = {
        "subject": '<path d="M6 3.75h7.2L18 8.55v11.7H6z"/><path d="M13.2 3.75v4.8H18"/>',
        "to": '<circle cx="12" cy="8" r="3.25"/><path d="M5.5 20c.45-4.1 2.6-6.15 6.5-6.15S18.05 15.9 18.5 20"/>',
        "cc": '<circle cx="9" cy="8.4" r="2.7"/><circle cx="16.3" cy="9.2" r="2.2"/><path d="M3.8 19c.4-3.45 2.15-5.2 5.2-5.2s4.85 1.75 5.25 5.2"/><path d="M14.1 14.25c2.9-.15 4.7 1.35 5.15 4.2"/>',
        "from": '<path d="M3.7 11.4 20.3 4.7l-6.7 16.6-2.2-7.3z"/><path d="m11.4 14 8.9-9.3"/>',
    }
    return (
        '<svg class="draft-meta-icon" viewBox="0 0 24 24" aria-hidden="true" '
        'fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round">{paths.get(kind, "")}</svg>'
    )


def _render_metadata(summary: dict, uid: str, folder: str) -> None:
    metadata = _source_metadata(summary, uid, folder)
    cc_value = str(metadata.get("cc") or "").strip()
    rows = [
        ("subject", "Subject", html.escape(_reply_subject(metadata["subject"])), _reply_subject(metadata["subject"])),
        ("to", "To", _collapsible_to_html(str(metadata["from"])), str(metadata["from"])),
    ]
    if cc_value and _collapsible_cc_html(cc_value):
        rows.append(("cc", "Cc", _collapsible_cc_html(cc_value), cc_value))
    from_value = str(st.session_state.get("email_address") or metadata["to"])
    rows.append(("from", "From", html.escape(from_value), from_value))

    row_html = "".join(
        '<div class="draft-meta-row">'
        f'<span class="draft-meta-icon-wrap">{_meta_icon(kind)}</span>'
        f'<span class="draft-meta-label">{html.escape(label)}</span>'
        f'<span class="draft-meta-value" title="{html.escape(title, quote=True)}">{value_html}</span>'
        '</div>'
        for kind, label, value_html, title in rows
    )
    st.markdown(
        '<div class="draft-modal-shell">'
        '<div class="draft-modal-note">'
        '<span class="draft-modal-note-icon">i</span>'
        '<span>You can review and edit this draft before sending.</span>'
        '</div>'
        f'<div class="draft-meta-card">{row_html}</div>'
        '</div>',
        unsafe_allow_html=True,
    )



def _render_attachment_risk_notices(assessments: list[dict]) -> None:
    risky = [item for item in assessments if item.get("risk") in {"warning", "high_risk"}]
    if not risky:
        return

    rows = []
    for item in risky:
        risk = str(item.get("risk") or "warning")
        css_class = "high" if risk == "high_risk" else "warning"
        icon = "!" if risk == "high_risk" else "&#9888;"
        rows.append(
            f'<div class="draft-attachment-risk-item {css_class}">'
            f'<span class="draft-attachment-risk-icon">{icon}</span>'
            '<div class="draft-attachment-risk-copy">'
            f'<div class="draft-attachment-risk-title">{html.escape(str(item.get("title") or "Attachment warning"))}</div>'
            f'<div class="draft-attachment-risk-file">{html.escape(str(item.get("filename") or "attachment"))} &middot; {html.escape(str(item.get("category") or "File"))}</div>'
            f'<div class="draft-attachment-risk-text">{html.escape(str(item.get("message") or ""))}</div>'
            '</div>'
            '</div>'
        )
    st.markdown(
        '<div class="draft-attachment-risk-list">' + ''.join(rows) + '</div>',
        unsafe_allow_html=True,
    )


def _send_risk_summary_html(assessments: list[dict]) -> str:
    risky = [item for item in assessments if item.get("risk") in {"warning", "high_risk"}]
    if not risky:
        return ""
    high_count = sum(1 for item in risky if item.get("risk") == "high_risk")
    warning_count = len(risky) - high_count
    if high_count:
        detail = f"{high_count} high-risk"
        if warning_count:
            detail += f" and {warning_count} warning-level"
        return (
            '<div class="draft-send-risk-summary high">'
            '<strong>Attachment risk check:</strong> '
            f'{detail} attachment{"s" if len(risky) != 1 else ""} included. '
            'Confirm that you trust the files and intended recipient before sending.'
            '</div>'
        )
    return (
        '<div class="draft-send-risk-summary warning">'
        '<strong>Attachment warning:</strong> '
        f'{warning_count} attachment{"s" if warning_count != 1 else ""} may contain active, compressed, macro-enabled, or packaged content. '
        'Your email provider may block them.'
        '</div>'
    )

def _uploaded_attachments(uploaded_files) -> list[dict]:
    attachments = []
    for uploaded in uploaded_files or []:
        data = uploaded.getvalue()
        if not data:
            continue
        attachments.append({
            "filename": uploaded.name or "attachment",
            "content_type": uploaded.type or "application/octet-stream",
            "size": len(data),
            "data": data,
        })
    return attachments


def _attachment_identity(attachment: dict) -> tuple[str, int, str]:
    data = attachment.get("data") or b""
    if isinstance(data, bytearray):
        data = bytes(data)
    digest = hashlib.sha256(data if isinstance(data, bytes) else b"").hexdigest()
    return (
        str(attachment.get("filename") or "attachment"),
        int(attachment.get("size") or (len(data) if isinstance(data, bytes) else 0)),
        digest,
    )


def _merge_attachments(*groups) -> list[dict]:
    """Merge saved and newly uploaded files without duplicating the same bytes."""
    merged: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for group in groups:
        for item in group or []:
            if not isinstance(item, dict):
                continue
            identity = _attachment_identity(item)
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(dict(item))
    return merged


def _attachment_assessments(saved_attachments: list[dict], uploaded_files) -> list[dict]:
    current_attachments = _merge_attachments(
        saved_attachments,
        _uploaded_attachments(uploaded_files),
    )
    return [
        classify_attachment(
            str(item.get("filename") or "attachment"),
            str(item.get("content_type") or ""),
        )
        for item in current_attachments
    ]


def _format_attachment_size(size: int) -> str:
    # Match the compact size label used by Streamlit's uploaded-file chip.
    value = max(0, int(size or 0))
    if value < 1024:
        return f"{float(value):.1f}B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f}KB"
    return f"{value / (1024 * 1024):.1f}MB"


def _render_draft_email_content(
    uid: str,
    folder: str = "INBOX",
    *,
    in_dialog: bool = False,
) -> None:
    uid = str(uid or "").strip()
    if not uid:
        st.error("No summarized email was selected.")
        return

    summary = _find_summary(uid, folder)
    if not summary:
        st.error("The AI summary is no longer available. Generate it again and retry.")
        return

    session_token = str(st.session_state.get("session_token") or "")
    draft_key = f"standalone_reply_draft_{uid}"
    backup_key = f"standalone_reply_backup_{uid}"
    instance_key = f"standalone_reply_editor_instance_{uid}"
    editor_instance = int(st.session_state.get(instance_key, 1) or 1)
    editor_key = f"standalone_reply_editor_{uid}_{editor_instance}"
    sent_key = f"standalone_reply_sent_{uid}"
    uploader_key = f"standalone_reply_attachments_{uid}"
    confirm_key = f"standalone_reply_confirm_send_{uid}"
    send_error_key = f"standalone_reply_send_error_{uid}"

    # Saved attachment bytes live outside the Streamlit uploader widget. The
    # uploader key is disposable UI state; these files must survive Save & Close
    # and status-driven AI reply regeneration for the same email draft.
    saved_attachments = get_reply_draft_attachments(session_token, uid)

    _render_metadata(summary, uid, folder)

    prepared = get_reply_draft(session_token, uid)
    cached_draft = str(st.session_state.get(draft_key, ""))
    backup_draft = str(st.session_state.get(backup_key, ""))

    # Restore from any surviving non-widget copy. The widget state is not the
    # source of truth because Streamlit may clean it up when the dialog closes.
    durable_draft = next(
        (value for value in (prepared, backup_draft, cached_draft) if value.strip()),
        "",
    )
    if not durable_draft.strip():
        st.warning("The draft is not ready yet. Close this dialog and try Draft email again.")
        return

    st.session_state[draft_key] = durable_draft
    st.session_state[backup_key] = durable_draft
    if not prepared.strip():
        save_reply_draft(session_token, uid, durable_draft)

    editor_value = str(st.session_state.get(editor_key, ""))
    if not editor_value.strip():
        st.session_state[editor_key] = durable_draft

    with st.container(key="draft_message_editor"):
        edited = st.text_area(
            "Message",
            key=editor_key,
            height=DRAFT_EDITOR_HEIGHT,
            disabled=bool(st.session_state.get(sent_key)),
            on_change=_persist_editor_change,
            args=(uid, draft_key, editor_key, backup_key),
        )
    if edited.strip():
        st.session_state[draft_key] = edited
        st.session_state[backup_key] = edited
        save_reply_draft(session_token, uid, edited)
    else:
        # Never save a blank emitted during a dialog transition. Keep the last
        # non-empty independent copy for this run and the next reopen.
        edited = str(st.session_state.get(backup_key) or st.session_state.get(draft_key) or prepared)

    with st.container(key="draft_attachment_area"):
        st.markdown(
            '<div class="draft-attachment-heading">'
            '<span class="draft-attachment-title">Attachments</span>'
            '<span class="draft-attachment-help">Add files to include with this email.</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        # Keep persisted attachments visually identical to freshly uploaded
        # file chips. Saving/reopening a draft must not downgrade the attachment
        # UI into a plain filename + large Remove button.
        with st.container(key=f"draft_attachment_toolbar_{uid}_{editor_instance}"):
            if saved_attachments:
                with st.container(key=f"draft_saved_attachment_chips_{uid}_{editor_instance}"):
                    for index, attachment in enumerate(list(saved_attachments)):
                        filename = html.escape(str(attachment.get("filename") or "attachment"))
                        size_label = html.escape(
                            _format_attachment_size(int(attachment.get("size") or 0))
                        )
                        with st.container(
                            key=f"draft_saved_attachment_chip_{uid}_{index}_{editor_instance}"
                        ):
                            file_col, remove_col = st.columns([1, 0.12], gap=None)
                            with file_col:
                                st.markdown(
                                    '<div class="draft-saved-file-copy">'
                                    '<span class="draft-saved-file-icon" aria-hidden="true">'
                                    '<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">'
                                    '<path d="M7 3.5h6.7L18.5 8v12.5H7z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>'
                                    '<path d="M13.5 3.8V8h4.4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>'
                                    '<path d="M9.5 12h6M9.5 15h6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>'
                                    '</svg>'
                                    '</span>'
                                    '<span class="draft-saved-file-meta">'
                                    f'<span class="draft-saved-file-name">{filename}</span>'
                                    f'<span class="draft-saved-file-size">{size_label}</span>'
                                    '</span>'
                                    '</div>',
                                    unsafe_allow_html=True,
                                )
                            with remove_col:
                                if st.button(
                                    "×",
                                    key=f"remove_saved_reply_attachment_{uid}_{index}_{editor_instance}",
                                    type="secondary",
                                    help=f"Remove {filename}",
                                ):
                                    remaining = [
                                        item
                                        for item_index, item in enumerate(saved_attachments)
                                        if item_index != index
                                    ]
                                    save_reply_draft_attachments(session_token, uid, remaining)
                                    _foreground_rerun()

            uploaded_files = st.file_uploader(
                "Insert attachments",
                accept_multiple_files=True,
                key=uploader_key,
                label_visibility="collapsed",
            )
        attachment_assessments = _attachment_assessments(saved_attachments, uploaded_files)
        _render_attachment_risk_notices(attachment_assessments)
        st.markdown(
            '<div class="draft-attachment-limit">Attachment limits and final acceptance depend on your email provider.</div>',
            unsafe_allow_html=True,
        )

    if st.session_state.get(sent_key):
        st.success("Reply sent successfully.")
        return

    save_close_clicked = False
    send_clicked = False
    confirm_send_clicked = False
    cancel_send_clicked = False

    if st.session_state.get(confirm_key):
        st.markdown(
            '<div class="draft-send-confirm-backdrop" aria-hidden="true"></div>',
            unsafe_allow_html=True,
        )
        with st.container(key="draft_send_confirmation"):
            st.markdown(
                '<div class="draft-send-confirm-copy">'
                '<div class="draft-send-confirm-icon">&#10003;</div>'
                '<div class="draft-send-confirm-message">'
                '<div class="draft-send-confirm-title">Ready to send?</div>'
                '<div class="draft-send-confirm-text">Please confirm that you reviewed the message, recipients, and attachments.</div>'
                '</div>'
                '</div>'
                + _send_risk_summary_html(attachment_assessments),
                unsafe_allow_html=True,
            )
            confirm_back_col, confirm_send_col = st.columns(2, gap="small")
            with confirm_back_col:
                cancel_send_clicked = st.button(
                    "Back to edit",
                    key=f"standalone_cancel_send_{uid}",
                    type="secondary",
                    use_container_width=True,
                )
            with confirm_send_col:
                confirm_send_clicked = st.button(
                    "Confirm and send",
                    icon=":material/send:",
                    key=f"standalone_confirm_send_{uid}",
                    type="primary",
                    use_container_width=True,
                )

    with st.container(key="draft_action_buttons"):
        col_space, col_discard, col_send = st.columns([1, 0.17, 0.18], gap="small")
        with col_space:
            st.empty()
        with col_discard:
            save_close_clicked = st.button(
                "Save & Close",
                icon=":material/save:",
                key=f"standalone_discard_reply_{uid}",
                type="secondary",
                use_container_width=True,
                help="Save the drafted message and close this dialog.",
            )
        with col_send:
            send_clicked = st.button(
                "Send reply",
                icon=":material/send:",
                key=f"standalone_send_reply_{uid}",
                type="primary",
                use_container_width=True,
                disabled=not edited.strip(),
            )

    if save_close_clicked:
        st.session_state.pop(send_error_key, None)
        # Save both user-editable parts of the draft before the dialog destroys
        # its widget state. AI text may later regenerate from a task/status change,
        # but user-added files remain attached to this draft until removed/sent.
        _persist_current_dialog_draft(uid)
        current_uploads = _uploaded_attachments(uploaded_files)
        save_reply_draft_attachments(
            session_token,
            uid,
            _merge_attachments(saved_attachments, current_uploads),
        )
        st.session_state.pop(confirm_key, None)
        if in_dialog:
            st.session_state.pop("draft_dialog_uid", None)
            _foreground_rerun()
        return

    if cancel_send_clicked:
        st.session_state.pop(confirm_key, None)
        _foreground_rerun()

    if send_clicked:
        _persist_current_dialog_draft(uid)
        st.session_state.pop(send_error_key, None)
        st.session_state[confirm_key] = True
        _foreground_rerun()

    if confirm_send_clicked:
        try:
            attachments = _merge_attachments(
                saved_attachments,
                _uploaded_attachments(uploaded_files),
            )
            with st.spinner("Sending reply..."):
                send_reply(
                    st.session_state.imap_client,
                    summary,
                    _outbound_body(edited),
                    attachments=attachments,
                )
            mark_provider_connection_ok()
            delete_reply_draft(session_token, uid)
            delete_reply_draft_attachments(session_token, uid)
            for key in (draft_key, editor_key, backup_key, instance_key, sent_key, uploader_key, confirm_key, send_error_key):
                st.session_state.pop(key, None)
            # Remove any stale editor widgets from earlier opens of this draft.
            editor_prefix = f"standalone_reply_editor_{uid}_"
            for key in list(st.session_state.keys()):
                if str(key).startswith(editor_prefix):
                    st.session_state.pop(key, None)
            if in_dialog:
                _clear_draft_dialog_state()
            # Keep the toast concise, but store exact reply context in the
            # global notification center for later review.
            reply_meta = _source_metadata(summary, uid, folder)
            reply_details = [
                f"Subject: {_reply_subject(reply_meta.get('subject'))}",
                f"To: {reply_meta.get('from') or 'Unknown recipient'}",
            ]
            if attachments:
                reply_details.append(
                    f"Attachments: {len(attachments)} file{'s' if len(attachments) != 1 else ''}"
                )
            push_summary_toast(
                "Reply sent successfully.",
                "success",
                title="Reply sent",
                details=reply_details,
                event_type="reply-sent",
                entity_id=uid,
            )
            _foreground_rerun(scope="app")
        except Exception as error:
            if is_network_error(error):
                mark_provider_connection_issue(error)
            message = provider_error_message(error, action="send")
            # Manual/user-triggered provider failures are Toast-only. Keep the
            # draft itself intact, but do not leave a second persistent error
            # card inside the editor and do not create a Bell notification.
            st.session_state.pop(send_error_key, None)
            push_summary_toast(
                message,
                "error",
                title="Reply not sent",
                event_type="reply-send-failed",
                entity_id=uid,
                notify_bell=False,
            )
            _foreground_rerun(scope="app")


@st.dialog(
    "Draft Email",
    width="large",
    icon=":material/mail:",
    dismissible=False,
)
def render_draft_email_dialog(uid: str, folder: str = "INBOX") -> None:
    # Open the prepared AI reply inside the current MailMind workspace.
    _render_draft_email_content(uid, folder, in_dialog=True)


def render_draft_email_window(uid: str, folder: str = "INBOX") -> None:
    # Legacy standalone renderer kept for old bookmarked action URLs.
    _render_draft_email_content(uid, folder, in_dialog=False)
