# Load the single application JavaScript file.

from pathlib import Path

import streamlit as st


def load_scripts() -> None:
    script_path = Path(__file__).with_name("main.js")
    if not script_path.is_file():
        raise FileNotFoundError(f"JavaScript file not found: {script_path}")
    javascript = script_path.read_text(encoding="utf-8")
    st.html(
        f"<script>{javascript}</script>",
        width="content",
        unsafe_allow_javascript=True,
    )


def emit_scroll_reset_marker(target: str) -> None:
    """Ask the already-loaded browser helper to scroll one stable list to top.

    Every request carries a new monotonic token. The old marker HTML was
    identical on every rerun, so React could legitimately reuse the same
    already-processed ``<template>`` node and the second/third pagination click
    would never trigger another scroll reset. A request token makes each page,
    filter, and tab reset observable without re-keying the large list itself.
    """
    normalized = str(target or "").strip().casefold()
    if normalized not in {"inbox", "summary", "todo"}:
        return

    seq_key = f"{normalized}_scroll_reset_request_seq"
    request_seq = int(st.session_state.get(seq_key, 0) or 0) + 1
    st.session_state[seq_key] = request_seq
    st.html(
        f'<template data-mailmind-scroll-target="{normalized}" '
        f'data-mailmind-scroll-request="{request_seq}"></template>',
        width="content",
    )
