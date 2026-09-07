"""Diagnostic tracing for intermittent Streamlit white/stale workspace failures.

This module is intentionally read-only with respect to MailMind business state.
It prints compact terminal events and mirrors them to ``debug/white_stale_trace.log``
so a user can send the exact action/rerun sequence after a blank page occurs.

No email body, subject, sender, recipient, or search text is logged.
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import json
import re
from pathlib import Path
import threading
import time
import uuid
from datetime import datetime
from typing import Any

import streamlit as st

from config import (
    WHITE_STALE_TRACE_ENABLED,
    WHITE_STALE_TRACE_MAX_LOG_BYTES,
    WHITE_STALE_TRACE_WATCHDOG_SECONDS,
)

_ENABLED = WHITE_STALE_TRACE_ENABLED
_ROOT = Path(__file__).resolve().parents[1]
_LOG_PATH = _ROOT / "debug" / "white_stale_trace.log"
_LOCK = threading.Lock()
_ORIGINAL_RERUN = None
_ORIGINAL_STOP = None
_ORIGINAL_WIDGETS: dict[str, Any] = {}
_RUN_STATUS: dict[str, str] = {}
_RUN_META: dict[str, dict[str, str]] = {}
_RUN_STATUS_LOCK = threading.Lock()


def trace_enabled() -> bool:
    return _ENABLED


def trace_log_path() -> str:
    return str(_LOG_PATH)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in list(value)[:20]]
    if isinstance(value, dict):
        safe = {}
        for key, item in list(value.items())[:30]:
            safe[str(key)] = _json_safe(item)
        return safe
    return str(value)


def _emit(event: str, **fields: Any) -> None:
    if not _ENABLED:
        return
    stamp = datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3]
    payload = {key: _json_safe(value) for key, value in fields.items() if value is not None}
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    line = f"[MMDBG {stamp}] {event} {text}" if payload else f"[MMDBG {stamp}] {event}"
    with _LOCK:
        print(line, flush=True)
        try:
            _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if _LOG_PATH.exists() and _LOG_PATH.stat().st_size >= WHITE_STALE_TRACE_MAX_LOG_BYTES:
                backup = _LOG_PATH.with_suffix(".log.1")
                try:
                    backup.unlink(missing_ok=True)
                    _LOG_PATH.replace(backup)
                except OSError:
                    _LOG_PATH.write_text("", encoding="utf-8")
            with _LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            # Terminal tracing must never fail the application because disk logging failed.
            pass


def _safe_get(key: str, default=None):
    try:
        return st.session_state.get(key, default)
    except Exception:
        return default


def _bool_present(key: str) -> bool:
    value = _safe_get(key)
    if isinstance(value, bool):
        return value
    return bool(str(value or "").strip())


def _safe_len(key: str) -> int:
    value = _safe_get(key)
    try:
        return len(value) if value is not None else 0
    except Exception:
        return 0


def state_snapshot() -> dict[str, Any]:
    """Return a compact, privacy-safe UI state snapshot for terminal diagnostics."""
    now = time.time()
    settle_until = float(_safe_get("foreground_ui_settle_until", 0.0) or 0.0)
    settle_ms = max(0, int((settle_until - now) * 1000)) if settle_until else 0
    return {
        "workspace": str(_safe_get("active_workspace", "") or ""),
        "generation": int(_safe_get("app_run_generation", 0) or 0),
        "root_render": bool(_safe_get("root_render_in_progress", False)),
        "foreground_guard": bool(_safe_get("foreground_navigation_guard", False)),
        "settle_ms": settle_ms,
        "auth": {
            "logged_in": bool(_safe_get("logged_in", False)),
            "logout_requested": bool(_safe_get("logout_requested", False)),
            "logout_in_progress": bool(_safe_get("logout_in_progress", False)),
        },
        "inbox": {
            "offset": int(_safe_get("inbox_offset", 0) or 0),
            "search_offset": int(_safe_get("inbox_search_offset", 0) or 0),
            "pending_page": str(_safe_get("inbox_pending_page_direction", "") or ""),
            "filter": str(_safe_get("inbox_filter", "") or ""),
            "spam_filter": str(_safe_get("spam_category_filter", "") or ""),
            "spam_detected": bool(_safe_get("spam_detected_only", False)),
            "search_active": bool(_safe_get("search_active", False)),
            "search_len": len(str(_safe_get("inbox_search_query", "") or "")),
            "selected": _bool_present("selected_uid"),
            "checked_count": _safe_len("checked_uids"),
            "rows": _safe_len("emails"),
        },
        "summary": {
            "offset": int(_safe_get("summary_offset", 0) or 0),
            "pending_page": str(_safe_get("summary_pending_page_direction", "") or ""),
            "search_len": len(str(_safe_get("summary_search_query", "") or "")),
            "unviewed": bool(_safe_get("summary_unread_only", False)),
            "task_filter": _safe_get("summary_task_filter"),
            "type_filter": _safe_get("summary_type_filter"),
            "status_filter": _safe_get("summary_status_filter"),
            "priority_filter": _safe_get("summary_priority_filter"),
            "selected": _bool_present("selected_summary_uid"),
            "rows": _safe_len("summaries"),
        },
        "todo": {
            "offset": int(_safe_get("todo_offset", 0) or 0),
            "pending_page": str(_safe_get("todo_pending_page_direction", "") or ""),
            "search_len": len(str(_safe_get("todo_search_query", "") or "")),
            "status_filter": _safe_get("todo_status_filter"),
            "priority_filter": _safe_get("todo_priority_filter"),
            "deadline_filter": _safe_get("todo_deadline_filter"),
            "attention_only": bool(_safe_get("todo_action_needed_only", False)),
            "dialog": _bool_present("todo_dialog_uid"),
        },
        "dialogs": {
            "draft": _bool_present("draft_dialog_uid"),
            "original": _bool_present("original_dialog_uid"),
            "spam": _bool_present("spam_email_dialog_uid"),
            "summary_settings": bool(_safe_get("summary_settings_dialog_open", False)),
        },
        "jobs": {
            "loading": bool(_safe_get("app_loading_active", False)),
            "summary": bool(_safe_get("summary_processing", False)),
            "draft": bool(_safe_get("draft_processing", False)),
        },
    }


def _session_id() -> str:
    try:
        value = str(st.session_state.get("_mmdbg_session_id") or "").strip()
        if not value:
            value = uuid.uuid4().hex[:8]
            st.session_state._mmdbg_session_id = value
        return value
    except Exception:
        return "no-session"


def _current_token() -> str:
    return str(_safe_get("_mmdbg_run_token", "") or "")


def _sanitize_action(action: str) -> str:
    text = str(action or "unknown").strip() or "unknown"
    for prefix in ("inbox-open:", "summary-open:", "todo-open:"):
        if text.startswith(prefix):
            raw = text[len(prefix):]
            digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:8]
            return f"{prefix}<id:{digest}>"
    return text


def _elapsed_since_state_timestamp(key: str) -> int | None:
    try:
        stamp = float(_safe_get(key, 0.0) or 0.0)
    except (TypeError, ValueError):
        return None
    if stamp <= 0.0:
        return None
    return max(0, int((time.time() - stamp) * 1000))


def _safe_widget_id(key: Any, label: Any = None) -> str:
    """Return a privacy-safe widget identifier suitable for diagnostic logs."""
    raw = str(key or "").strip()
    if raw:
        sensitive_shape = bool(
            "@" in raw
            or len(raw) > 72
            or re.search(r"[0-9a-fA-F]{12,}", raw)
            or re.search(r"\d{8,}", raw)
        )
        if not sensitive_shape and re.fullmatch(r"[A-Za-z0-9_.:-]+", raw):
            return raw
        digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:10]
        prefix = re.split(r"[^A-Za-z0-9_-]+", raw, maxsplit=1)[0][:24] or "key"
        return f"{prefix}:<key:{digest}>"

    label_text = str(label or "").strip()
    if label_text:
        digest = hashlib.sha1(label_text.encode("utf-8", errors="ignore")).hexdigest()[:10]
        return f"<label:{digest}>"
    return "<anonymous>"


def _callback_name(callback: Any) -> str:
    name = str(getattr(callback, "__qualname__", "") or getattr(callback, "__name__", "") or "")
    if not name:
        name = callback.__class__.__name__ if callback is not None else "none"
    return name[:120]


def _remember_interaction(widget_type: str, widget_id: str, phase: str) -> None:
    try:
        now = time.time()
        st.session_state._mmdbg_last_interaction = f"{widget_type}:{widget_id}:{phase}"
        st.session_state._mmdbg_last_interaction_at = now
    except Exception:
        pass


def _emit_interaction(
    widget_type: str,
    widget_id: str,
    phase: str,
    *,
    callback: Any = None,
    elapsed_ms: int | None = None,
    **fields: Any,
) -> None:
    _remember_interaction(widget_type, widget_id, phase)
    _emit(
        "INTERACTION",
        session=_session_id(),
        run=_current_token(),
        widget=widget_type,
        widget_id=widget_id,
        phase=phase,
        callback=_callback_name(callback) if callback is not None else None,
        elapsed_ms=elapsed_ms,
        workspace=str(_safe_get("active_workspace", "") or ""),
        **fields,
    )


def _wrap_widget_callback(callback: Any, widget_type: str, widget_id: str):
    if not callable(callback):
        return callback
    if getattr(callback, "_mailmind_interaction_traced", False):
        return callback

    @functools.wraps(callback)
    def traced_callback(*args, **kwargs):
        started = time.monotonic()
        _emit_interaction(widget_type, widget_id, "callback-start", callback=callback)
        try:
            return callback(*args, **kwargs)
        except Exception as exc:
            _emit_interaction(
                widget_type,
                widget_id,
                "callback-error",
                callback=callback,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                error_type=type(exc).__name__,
                error=str(exc)[:250],
            )
            raise
        finally:
            _emit_interaction(
                widget_type,
                widget_id,
                "callback-end",
                callback=callback,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    traced_callback._mailmind_interaction_traced = True
    return traced_callback


def _value_fingerprint(value: Any) -> str:
    try:
        raw = repr(value)
    except Exception:
        raw = f"<{type(value).__name__}>"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _remember_widget_value(widget_type: str, widget_id: str, value: Any) -> bool:
    """Return True only when a previously mounted non-button widget changed."""
    state_key = f"{widget_type}:{widget_id}"
    fingerprint = _value_fingerprint(value)
    try:
        fingerprints = dict(st.session_state.get("_mmdbg_widget_fingerprints") or {})
        previous = fingerprints.get(state_key)
        fingerprints[state_key] = fingerprint
        if len(fingerprints) > 256:
            # Bound diagnostics during long sessions without touching widget state.
            fingerprints = dict(list(fingerprints.items())[-192:])
        st.session_state._mmdbg_widget_fingerprints = fingerprints
        return previous is not None and previous != fingerprint
    except Exception:
        return False


def _install_widget_diagnostics() -> None:
    """Trace Streamlit user interactions centrally without changing widget behavior.

    Callback START/END timestamps expose slow callbacks. For controls without a
    callback, return-value/change events still leave a privacy-safe breadcrumb.
    No label text, input text, selected option text, or uploaded filename is logged.
    """
    widget_specs = {
        "button": "on_click",
        "form_submit_button": "on_click",
        "download_button": "on_click",
        "checkbox": "on_change",
        "radio": "on_change",
        "text_input": "on_change",
        "text_area": "on_change",
        "file_uploader": "on_change",
        "selectbox": "on_change",
        "multiselect": "on_change",
        "toggle": "on_change",
        "number_input": "on_change",
        "date_input": "on_change",
        "time_input": "on_change",
        "slider": "on_change",
        "select_slider": "on_change",
        "pills": "on_change",
        "segmented_control": "on_change",
    }
    button_like = {"button", "form_submit_button", "download_button"}

    for widget_name, callback_kw in widget_specs.items():
        original = getattr(st, widget_name, None)
        if original is None or not callable(original):
            continue
        if getattr(original, "_mailmind_widget_traced", False):
            continue
        _ORIGINAL_WIDGETS.setdefault(widget_name, original)

        def make_wrapper(name, callback_name_kw, original_fn):
            @functools.wraps(original_fn)
            def traced_widget(*args, **kwargs):
                label = kwargs.get("label", args[0] if args else None)
                widget_id = _safe_widget_id(kwargs.get("key"), label)
                callback = kwargs.get(callback_name_kw)
                has_callback = callable(callback)
                if has_callback:
                    kwargs = dict(kwargs)
                    kwargs[callback_name_kw] = _wrap_widget_callback(callback, name, widget_id)

                started = time.monotonic()
                try:
                    result = original_fn(*args, **kwargs)
                except Exception as exc:
                    _emit_interaction(
                        name,
                        widget_id,
                        "widget-error",
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                        error_type=type(exc).__name__,
                        error=str(exc)[:250],
                    )
                    raise

                render_ms = int((time.monotonic() - started) * 1000)
                if name in button_like:
                    if bool(result):
                        _emit_interaction(name, widget_id, "triggered", elapsed_ms=render_ms)
                elif not has_callback and _remember_widget_value(name, widget_id, result):
                    extra = {}
                    if name in {"text_input", "text_area"}:
                        try:
                            extra["value_len"] = len(result or "")
                        except Exception:
                            pass
                    _emit_interaction(name, widget_id, "changed", elapsed_ms=render_ms, **extra)
                return result

            traced_widget._mailmind_widget_traced = True
            return traced_widget

        setattr(st, widget_name, make_wrapper(widget_name, callback_kw, original))


def trace_action(action: str, *, outcome: str = "event", **fields: Any) -> None:
    """Record a user/process action without logging message content."""
    if not _ENABLED:
        return
    clean_action = _sanitize_action(action)
    previous_action_age_ms = _elapsed_since_state_timestamp("_mmdbg_last_action_at")
    interaction_age_ms = _elapsed_since_state_timestamp("_mmdbg_last_interaction_at")
    try:
        st.session_state._mmdbg_last_action = clean_action
        st.session_state._mmdbg_last_action_at = time.time()
    except Exception:
        pass
    token = _current_token()
    if token:
        with _RUN_STATUS_LOCK:
            _RUN_META.setdefault(token, {})["last_action"] = clean_action
    _emit(
        "ACTION",
        session=_session_id(),
        run=token,
        action=clean_action,
        outcome=outcome,
        workspace=str(_safe_get("active_workspace", "") or ""),
        previous_action_age_ms=previous_action_age_ms,
        interaction_age_ms=interaction_age_ms,
        **fields,
    )


def trace_stage(stage: str, **fields: Any) -> None:
    if not _ENABLED:
        return
    stage = str(stage or "unknown")
    try:
        st.session_state._mmdbg_stage = stage
    except Exception:
        pass
    token = _current_token()
    if token:
        with _RUN_STATUS_LOCK:
            _RUN_META.setdefault(token, {})["stage"] = stage
    _emit(
        "STAGE",
        session=_session_id(),
        run=token,
        stage=stage,
        workspace=str(_safe_get("active_workspace", "") or ""),
        since_action_ms=_elapsed_since_state_timestamp("_mmdbg_last_action_at"),
        since_interaction_ms=_elapsed_since_state_timestamp("_mmdbg_last_interaction_at"),
        **fields,
    )


def _watch_run(token: str, session_id: str, started: float) -> None:
    time.sleep(WHITE_STALE_TRACE_WATCHDOG_SECONDS)
    with _RUN_STATUS_LOCK:
        status = _RUN_STATUS.get(token, "unknown")
        meta = dict(_RUN_META.get(token, {}))
    if status == "running":
        _emit(
            "RUN-SLOW-SUSPECT",
            session=session_id,
            run=token,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            last_action=meta.get("last_action", ""),
            last_stage=meta.get("stage", ""),
            note="Full app run has not reached COMPLETE/RERUN/STOP after watchdog window",
        )


def begin_app_run() -> str:
    """Mark one full Streamlit app run and flag an unexplained prior abort."""
    if not _ENABLED:
        return ""
    sid = _session_id()
    previous_status = str(_safe_get("_mmdbg_run_status", "") or "")
    previous_token = str(_safe_get("_mmdbg_run_token", "") or "")
    previous_stage = str(_safe_get("_mmdbg_stage", "") or "")
    previous_action = str(_safe_get("_mmdbg_last_action", "") or "")
    previous_interaction = str(_safe_get("_mmdbg_last_interaction", "") or "")
    action_to_run_ms = _elapsed_since_state_timestamp("_mmdbg_last_action_at")
    interaction_to_run_ms = _elapsed_since_state_timestamp("_mmdbg_last_interaction_at")
    if previous_status == "running" and previous_token:
        _emit(
            "PREVIOUS-RUN-INCOMPLETE-SUSPECT",
            session=sid,
            previous_run=previous_token,
            last_stage=previous_stage,
            last_action=previous_action,
            note="Previous full run started but never logged COMPLETE/RERUN/STOP",
        )

    seq = int(_safe_get("_mmdbg_run_seq", 0) or 0) + 1
    token = f"{sid}-{seq}"
    started = time.monotonic()
    st.session_state._mmdbg_run_seq = seq
    st.session_state._mmdbg_run_token = token
    st.session_state._mmdbg_run_started = started
    st.session_state._mmdbg_run_status = "running"
    st.session_state._mmdbg_stage = "run-start"
    with _RUN_STATUS_LOCK:
        _RUN_STATUS[token] = "running"
        _RUN_META[token] = {"last_action": previous_action, "stage": "run-start"}
    _emit(
        "RUN-START",
        session=sid,
        run=token,
        previous_status=previous_status or None,
        last_action=previous_action or None,
        last_interaction=previous_interaction or None,
        action_to_run_ms=action_to_run_ms,
        interaction_to_run_ms=interaction_to_run_ms,
        state=state_snapshot(),
    )
    thread = threading.Thread(
        target=_watch_run,
        args=(token, sid, started),
        name=f"mailmind-white-stale-watch-{seq}",
        daemon=True,
    )
    thread.start()
    return token


def complete_app_run() -> None:
    if not _ENABLED:
        return
    token = _current_token()
    started = float(_safe_get("_mmdbg_run_started", time.monotonic()) or time.monotonic())
    st.session_state._mmdbg_run_status = "complete"
    st.session_state._mmdbg_stage = "complete"
    with _RUN_STATUS_LOCK:
        if token:
            _RUN_STATUS[token] = "complete"
    _emit(
        "RUN-COMPLETE",
        session=_session_id(),
        run=token,
        elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
        since_action_ms=_elapsed_since_state_timestamp("_mmdbg_last_action_at"),
        since_interaction_ms=_elapsed_since_state_timestamp("_mmdbg_last_interaction_at"),
        state=state_snapshot(),
    )


def _caller() -> str:
    try:
        frame = inspect.stack()[2]
        path = Path(frame.filename).name
        return f"{path}:{frame.lineno}:{frame.function}"
    except Exception:
        return "unknown"


def install_streamlit_diagnostics() -> None:
    """Trace rerun/stop plus privacy-safe server-side widget interactions."""
    global _ORIGINAL_RERUN, _ORIGINAL_STOP
    if not _ENABLED:
        return

    if not getattr(st.rerun, "_mailmind_white_stale_traced", False):
        _ORIGINAL_RERUN = st.rerun

        @functools.wraps(_ORIGINAL_RERUN)
        def traced_rerun(*args, **kwargs):
            scope = kwargs.get("scope")
            token = _current_token()
            try:
                st.session_state._mmdbg_run_status = "rerun_requested"
                st.session_state._mmdbg_stage = "rerun-requested"
            except Exception:
                pass
            with _RUN_STATUS_LOCK:
                if token:
                    _RUN_STATUS[token] = "rerun_requested"
            _emit(
                "RERUN-REQUEST",
                session=_session_id(),
                run=token,
                scope=scope or "app-default",
                caller=_caller(),
                last_action=str(_safe_get("_mmdbg_last_action", "") or ""),
                last_interaction=str(_safe_get("_mmdbg_last_interaction", "") or ""),
                since_action_ms=_elapsed_since_state_timestamp("_mmdbg_last_action_at"),
                since_interaction_ms=_elapsed_since_state_timestamp("_mmdbg_last_interaction_at"),
                state=state_snapshot(),
            )
            return _ORIGINAL_RERUN(*args, **kwargs)

        traced_rerun._mailmind_white_stale_traced = True
        st.rerun = traced_rerun

    if not getattr(st.stop, "_mailmind_white_stale_traced", False):
        _ORIGINAL_STOP = st.stop

        @functools.wraps(_ORIGINAL_STOP)
        def traced_stop(*args, **kwargs):
            token = _current_token()
            try:
                st.session_state._mmdbg_run_status = "stop_requested"
                st.session_state._mmdbg_stage = "stop-requested"
            except Exception:
                pass
            with _RUN_STATUS_LOCK:
                if token:
                    _RUN_STATUS[token] = "stop_requested"
            _emit(
                "STOP-REQUEST",
                session=_session_id(),
                run=token,
                caller=_caller(),
                last_action=str(_safe_get("_mmdbg_last_action", "") or ""),
                last_interaction=str(_safe_get("_mmdbg_last_interaction", "") or ""),
                since_action_ms=_elapsed_since_state_timestamp("_mmdbg_last_action_at"),
                since_interaction_ms=_elapsed_since_state_timestamp("_mmdbg_last_interaction_at"),
                state=state_snapshot(),
            )
            return _ORIGINAL_STOP(*args, **kwargs)

        traced_stop._mailmind_white_stale_traced = True
        st.stop = traced_stop

    _install_widget_diagnostics()


def trace_exception(context: str, exc: BaseException) -> None:
    _emit(
        "EXCEPTION",
        session=_session_id(),
        run=_current_token(),
        context=context,
        error_type=type(exc).__name__,
        error=str(exc)[:500],
        last_action=str(_safe_get("_mmdbg_last_action", "") or ""),
        last_stage=str(_safe_get("_mmdbg_stage", "") or ""),
        state=state_snapshot(),
    )
