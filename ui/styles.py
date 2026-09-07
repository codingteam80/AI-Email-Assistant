# Load the single application stylesheet.

from pathlib import Path

import streamlit as st


def load_styles() -> None:
    css_path = Path(__file__).with_name("main.css")
    if not css_path.is_file():
        raise FileNotFoundError(f"Stylesheet not found: {css_path}")
    css = css_path.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
