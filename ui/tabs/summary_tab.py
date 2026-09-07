# AI Summary workspace laid out like the Inbox workspace.
import streamlit as st

from config import UI_DEBOUNCE_FAST_SECONDS, UI_FOREGROUND_SETTLE_SECONDS

from controllers.summary_controller import open_summary
from ui.summary_list import render_summary_list
from ui.summary_reader import render_summary_reader
from services.ui_interaction_service import claim_foreground_interaction
from services.white_stale_trace_service import trace_action


def _open_summary_from_list(uid: str) -> None:
    uid = str(uid or "")
    if not uid:
        return
    if not claim_foreground_interaction(
        f"summary-open:{uid}", debounce_seconds=UI_DEBOUNCE_FAST_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("summary-card-open")
    open_summary(uid)


def render_summary_tab():
    summaries = st.session_state.summaries
    with st.container(border=False, key="summary_workspace"):
        col_list, col_content = st.columns([0.4, 0.6], gap="large")
        with col_list:
            with st.container(key="summary_outer_pane"):
                st.markdown('<div class="mailmind-workspace-header"><div class="mailmind-workspace-title">AI Summary</div><div class="mailmind-workspace-controls mailmind-workspace-controls-empty"></div></div>', unsafe_allow_html=True)
                render_summary_list(
                    summaries,
                    on_open=_open_summary_from_list,
                )
        with col_content:
            with st.container(key="summary_content_outer_pane"):
                st.markdown(
                    '<div class="mailmind-workspace-header"><div class="mailmind-workspace-title">Summary Content</div><div class="mailmind-workspace-controls mailmind-workspace-controls-empty"></div></div>',
                    unsafe_allow_html=True,
                )
                selected = next(
                    (item for item in summaries if str(item["uid"]) == str(
                        st.session_state.selected_summary_uid
                    )),
                    None,
                )
                render_summary_reader(selected)
