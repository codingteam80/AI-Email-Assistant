import html
import re

import streamlit as st


def _progress_from_detail(detail: str) -> tuple[str, int | None]:
    # Normalize loader detail and derive a determinate percentage when possible.
    #
    # MailMind currently supplies either percentages (``42%``) or completed-item
    # counts (``3 of 11``). Count details are converted to a combined label so
    # long-running summary jobs show both completed emails and percent.
    text = str(detail or "").strip()
    if not text:
        return "", None

    if text.casefold() == "done":
        return "100%", 100

    percent_match = re.fullmatch(r"\s*(\d{1,3})\s*%\s*", text)
    if percent_match:
        value = max(0, min(int(percent_match.group(1)), 100))
        return f"{value}%", value

    count_match = re.fullmatch(
        r"\s*(\d+)\s+of\s+(\d+)\s*",
        text,
        flags=re.IGNORECASE,
    )
    if count_match:
        current = max(0, int(count_match.group(1)))
        total = max(0, int(count_match.group(2)))
        if total > 0:
            current = min(current, total)
            value = max(0, min(round((current / total) * 100), 100))
            return f"{current} of {total} • {value}%", value
        return f"{current} of {total}", None

    return text, None


def render_app_loading_overlay(
    target,
    title: str = "Please wait...",
    subtitle: str = "Loading...",
    detail: str = "",
    *,
    variant: str = "",
) -> None:
    # Render a centered fixed loading modal on top of the workspace.
    # Variants are marked on the overlay itself so one loader can never inherit
    # another workflow's CSS from a stale Streamlit fragment/container.
    title = html.escape(title or "Please wait...")
    subtitle = html.escape(subtitle or "Loading...")
    normalized_detail, progress_value = _progress_from_detail(detail)
    detail_html = (
        f'<div class="app-loading-detail">{html.escape(normalized_detail)}</div>'
        if normalized_detail
        else ""
    )
    progress_html = ""
    if progress_value is not None:
        progress_html = (
            '<progress class="app-loading-progress" '
            f'value="{progress_value}" max="100" aria-label="Loading progress">'
            f'{progress_value}%'
            "</progress>"
        )

    overlay_class = "app-loading-overlay"
    if str(variant or "").strip().casefold() == "summary":
        overlay_class += " app-loading-overlay--summary"

    markup = f"""
<div role="status" aria-live="polite" class="{overlay_class}">
  <div class="app-loading-card">
    <div class="app-loading-spinner" aria-hidden="true"></div>
    <div class="app-loading-title">{title}</div>
    <div class="app-loading-subtitle">{subtitle}</div>
    {detail_html}
    {progress_html}
  </div>
</div>
"""
    target.markdown(markup.strip(), unsafe_allow_html=True)


def clear_app_loading_overlay(target) -> None:
    if target is not None:
        target.empty()


def set_app_loading_state(
    title: str = "Please wait...",
    subtitle: str = "Loading...",
    detail: str = "",
) -> None:
    st.session_state.app_loading_active = True
    st.session_state.app_loading_title = title or "Please wait..."
    st.session_state.app_loading_subtitle = subtitle or "Loading..."
    st.session_state.app_loading_detail = detail or ""


def update_app_loading_state(
    title: str | None = None,
    subtitle: str | None = None,
    detail: str | None = None,
) -> None:
    st.session_state.app_loading_active = True
    if title is not None:
        st.session_state.app_loading_title = title or "Please wait..."
    if subtitle is not None:
        st.session_state.app_loading_subtitle = subtitle or "Loading..."
    if detail is not None:
        st.session_state.app_loading_detail = detail or ""


def clear_app_loading_state() -> None:
    st.session_state.app_loading_active = False
    st.session_state.app_loading_title = "Please wait..."
    st.session_state.app_loading_subtitle = "Loading..."
    st.session_state.app_loading_detail = ""


def render_active_app_loading_overlay(target) -> None:
    if not st.session_state.get("app_loading_active"):
        return

    summary_processing = bool(st.session_state.get("summary_processing"))
    render_app_loading_overlay(
        target,
        title=st.session_state.get("app_loading_title", "Please wait..."),
        subtitle=st.session_state.get("app_loading_subtitle", "Loading..."),
        # Keep the latest Summary count/progress visible on the stable root card
        # immediately when the worker starts. The timed fragment takes over the
        # live updates without exposing a transient blank loader between the
        # preparation frame and the first fragment tick.
        detail=st.session_state.get("app_loading_detail", ""),
        variant=(
            "summary"
            if (
                summary_processing
                or st.session_state.get("manual_summary_prepare_overlay_owned", False)
                or st.session_state.get("draft_processing")
            )
            else ""
        ),
    )


def render_summary_live_progress(detail: str = "") -> None:
    # Repaint only the changing Summary count/progress bar. Keeping this tiny
    # layer separate from the root loader prevents the spinner/card/backdrop
    # from restarting on every polling-fragment tick.
    normalized_detail, progress_value = _progress_from_detail(detail)
    if not normalized_detail and progress_value is None:
        return

    detail_html = (
        f'<div class="summary-live-progress-detail">{html.escape(normalized_detail)}</div>'
        if normalized_detail
        else ""
    )
    progress_html = ""
    if progress_value is not None:
        progress_html = (
            '<progress class="summary-live-progress-bar" '
            f'value="{progress_value}" max="100" aria-label="Summary progress">'
            f'{progress_value}%'
            '</progress>'
        )

    with st.container(key="summary_live_progress_overlay"):
        st.markdown(
            (
                "<style>"
                "body:has(.st-key-summary_live_progress_overlay) "
                ".app-loading-overlay--summary .app-loading-detail,"
                "body:has(.st-key-summary_live_progress_overlay) "
                ".app-loading-overlay--summary .app-loading-progress"
                "{display:none!important;}"
                "</style>"
                f'<div class="summary-live-progress">{detail_html}{progress_html}</div>'
            ),
            unsafe_allow_html=True,
        )
