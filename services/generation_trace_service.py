# Correlated live tracing for Summary and Reply Draft generation.
# Timing/metadata only: never stores prompts, email bodies, subjects, addresses, or generated text.
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime

from config import GENERATION_TRACE_ENABLED


_state = threading.local()
_file_lock = threading.Lock()
_TRACE_ENABLED = GENERATION_TRACE_ENABLED


def _results_path() -> str:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(project_root, "test", "results")
    os.makedirs(results_dir, exist_ok=True)
    return os.path.join(results_dir, "live_generation_trace.jsonl")


def new_generation_job_id(kind: str) -> str:
    prefix = "S" if str(kind or "").strip().casefold().startswith("sum") else "D"
    stamp = datetime.now().strftime("%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:5]}"


def _safe_value(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe_value(item) for item in list(value)[:20]]
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in list(value.items())[:20]}
    return str(value)


def _emit(kind: str, job_id: str, stage: str, *, elapsed: float | None = None, **fields) -> None:
    if not _TRACE_ENABLED:
        return
    event = {
        "at": datetime.now().isoformat(timespec="milliseconds"),
        "kind": str(kind or "GEN").upper(),
        "job_id": str(job_id or "-") or "-",
        "stage": str(stage or "event"),
    }
    if elapsed is not None:
        try:
            event["elapsed_seconds"] = round(max(0.0, float(elapsed)), 4)
        except (TypeError, ValueError):
            pass
    for key, value in fields.items():
        if value is not None and value != "":
            event[str(key)] = _safe_value(value)

    compact_fields = []
    if "elapsed_seconds" in event:
        compact_fields.append(f"elapsed={event['elapsed_seconds']:.3f}s")
    for key in (
        "origin", "mode", "items", "item", "operation", "status", "calls", "summaries", "thread_mode",
        "thread_chars", "latest_chars", "facts_chars", "user_chars", "system_chars", "repair_context_chars",
        "actions", "exact_values", "ownership_other", "audit_chars", "source_chars", "segment", "segments",
        "repair_needed", "repair_reasons", "issue_counts", "remaining_reasons", "remaining_counts",
    ):
        if key in event:
            compact_fields.append(f"{key}={event[key]}")
    suffix = (" " + " ".join(compact_fields)) if compact_fields else ""
    print(
        f"[Generation trace] {event['kind']} job={event['job_id']} stage={event['stage']}{suffix}",
        flush=True,
    )

    try:
        path = _results_path()
        with _file_lock:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        # Tracing must never affect application behavior.
        pass


def trace_launch(kind: str, job_id: str, **fields) -> None:
    _emit(kind, job_id, "launch", **fields)


def begin_generation_trace(kind: str, job_id: str, **fields) -> None:
    current = {
        "kind": str(kind or "GEN").upper(),
        "job_id": str(job_id or "-") or "-",
        "started": time.perf_counter(),
        "ollama_calls": 0,
    }
    _state.current = current
    _emit(current["kind"], current["job_id"], "worker_start", **fields)


def trace_event(stage: str, *, elapsed: float | None = None, **fields) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return
    _emit(current["kind"], current["job_id"], stage, elapsed=elapsed, **fields)


def trace_external(kind: str, job_id: str, stage: str, *, elapsed: float | None = None, **fields) -> None:
    _emit(kind, job_id, stage, elapsed=elapsed, **fields)


def current_trace_context() -> dict:
    current = getattr(_state, "current", None)
    return dict(current) if isinstance(current, dict) else {}


def note_ollama_call(operation: str) -> dict:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return {}
    current["ollama_calls"] = int(current.get("ollama_calls") or 0) + 1
    return {
        "kind": current.get("kind") or "GEN",
        "job_id": current.get("job_id") or "-",
        "call_index": current["ollama_calls"],
        "operation": str(operation or "ollama"),
    }


def finish_generation_trace(status: str = "ok", **fields) -> None:
    current = getattr(_state, "current", None)
    if not isinstance(current, dict):
        return
    elapsed = time.perf_counter() - float(current.get("started") or time.perf_counter())
    fields.setdefault("calls", int(current.get("ollama_calls") or 0))
    fields.setdefault("status", str(status or "ok"))
    _emit(current["kind"], current["job_id"], "worker_done", elapsed=elapsed, **fields)
    _state.current = None


def set_next_ollama_operation(operation: str) -> None:
    # One-shot label for plain-text Ollama calls. Keeping this outside the
    # _request_text() signature preserves compatibility with existing tests/mocks.
    _state.next_ollama_operation = str(operation or "").strip()


def consume_next_ollama_operation(default: str = "reply draft") -> str:
    operation = str(getattr(_state, "next_ollama_operation", "") or "").strip()
    _state.next_ollama_operation = ""
    return operation or str(default or "reply draft")
