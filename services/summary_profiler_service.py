# In-process timing telemetry for the summary pipeline.
# Profiling records timings only; it never changes summary inputs or outputs.
from __future__ import annotations

from copy import deepcopy
import threading


_state = threading.local()


def _seconds_from_ns(value) -> float:
    try:
        return max(0, int(value or 0)) / 1_000_000_000
    except (TypeError, ValueError):
        return 0.0


def begin_summary_profile(email: dict) -> None:
    _state.current = {
        "subject": str(email.get("subject") or ""),
        "stages": {},
        "action_audit_ran": False,
        "low_information_fast_path": False,
        "ollama_calls": [],
    }


def record_summary_stage(name: str, seconds: float) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return
    try:
        value = max(0.0, float(seconds))
    except (TypeError, ValueError):
        value = 0.0
    current.setdefault("stages", {})[str(name)] = value


def set_summary_profile_flag(name: str, value) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return
    current[str(name)] = value


def record_summary_ollama_call(
    envelope: dict,
    operation: str,
    *,
    wall_seconds: float = 0.0,
    retry: bool = False,
) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict) or not isinstance(envelope, dict):
        return

    try:
        wall = max(0.0, float(wall_seconds))
    except (TypeError, ValueError):
        wall = 0.0

    current.setdefault("ollama_calls", []).append({
        "operation": str(operation),
        "retry": bool(retry),
        "wall_seconds": wall,
        "server_total_seconds": _seconds_from_ns(envelope.get("total_duration")),
        "load_seconds": _seconds_from_ns(envelope.get("load_duration")),
        "prompt_eval_seconds": _seconds_from_ns(envelope.get("prompt_eval_duration")),
        "eval_seconds": _seconds_from_ns(envelope.get("eval_duration")),
        "input_tokens": int(envelope.get("prompt_eval_count") or 0),
        "output_tokens": int(envelope.get("eval_count") or 0),
    })


def finish_summary_profile(total_seconds: float) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return
    try:
        current["total_seconds"] = max(0.0, float(total_seconds))
    except (TypeError, ValueError):
        current["total_seconds"] = 0.0
    _state.last = deepcopy(current)
    _state.current = None


def get_last_summary_profile() -> dict:
    last = getattr(_state, "last", None)
    return deepcopy(last) if isinstance(last, dict) else {}


def clear_summary_profile() -> None:
    _state.current = None
    _state.last = None
