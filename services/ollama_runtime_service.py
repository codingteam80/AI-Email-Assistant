# Shared Ollama runtime helpers for warm-up, keep-alive, and timing telemetry.
import json
import threading
from contextlib import contextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from services.generation_trace_service import current_trace_context, note_ollama_call

from config import (
    OLLAMA_KEEP_ALIVE,
    OLLAMA_MODEL,
    OLLAMA_REQUEST_TIMEOUT,
    OLLAMA_TIMING_LOG_ENABLED,
    OLLAMA_URL,
)


_preload_lock = threading.Lock()
_generation_request_lock = threading.Lock()
_preload_started = False


@contextmanager
def ollama_generation_slot():
    """Serialize model HTTP calls without disabling unrelated user actions.

    Auto Summary, reply drafting, and any other model-backed task may be started
    from different workers, but the local Ollama runtime should receive only one
    generation request at a time. UI/state operations remain fully concurrent.
    """
    _generation_request_lock.acquire()
    try:
        yield
    finally:
        _generation_request_lock.release()


def user_facing_ai_error(error, *, action: str = "summary") -> str:
    # Never surface Ollama/llama-server payloads, exit codes, model internals, or
    # transport traces directly in the product UI. Keep those exceptions in the
    # terminal/debug trace and give the user one short recovery instruction.
    raw = str(error or "").strip()
    lowered = raw.casefold()
    runtime_markers = (
        "ollama",
        "llama-server",
        "connection refused",
        "urlopen",
        "winerror",
        "nstatus",
        "exit status",
        "model not found",
        "model is not installed",
        "timed out",
        "timeout",
    )
    if any(marker in lowered for marker in runtime_markers):
        return "AI is currently unavailable. Start or restart Ollama, then try again."

    action_name = str(action or "summary").strip().casefold()
    if action_name == "draft":
        return "The draft could not be generated. Please try again."
    return "The summary could not be generated. Please try again."


def _seconds_from_ns(value) -> float:
    try:
        return max(0, int(value or 0)) / 1_000_000_000
    except (TypeError, ValueError):
        return 0.0


def log_ollama_timing(envelope: dict, operation: str) -> None:
    # Ollama reports server timings in nanoseconds. Logging them makes it possible
    # to separate model loading from prompt evaluation and token generation.
    if not OLLAMA_TIMING_LOG_ENABLED or not isinstance(envelope, dict):
        return

    total = _seconds_from_ns(envelope.get("total_duration"))
    load = _seconds_from_ns(envelope.get("load_duration"))
    prompt = _seconds_from_ns(envelope.get("prompt_eval_duration"))
    generation = _seconds_from_ns(envelope.get("eval_duration"))
    prompt_tokens = int(envelope.get("prompt_eval_count") or 0)
    output_tokens = int(envelope.get("eval_count") or 0)

    if not any((total, load, prompt, generation, prompt_tokens, output_tokens)):
        return

    trace = note_ollama_call(operation)
    trace_prefix = ""
    if trace:
        trace_prefix = (
            f"{trace.get('kind')} job={trace.get('job_id')} "
            f"call={trace.get('call_index')} "
        )
    print(
        "[Ollama timing] "
        f"{trace_prefix}{operation}: total={total:.2f}s load={load:.2f}s "
        f"prompt={prompt:.2f}s eval={generation:.2f}s "
        f"input_tokens={prompt_tokens} output_tokens={output_tokens}",
        flush=True,
    )


def preload_ollama_model() -> bool:
    # An empty chat request loads the model without generating user content.
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
    }
    request = Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with ollama_generation_slot():
            with urlopen(request, timeout=OLLAMA_REQUEST_TIMEOUT) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        log_ollama_timing(envelope, "model preload")
        return True
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, TypeError, ValueError):
        # Warm-up is an optimization only; failure must never block the app.
        return False


def start_ollama_preload() -> bool:
    # Start only once per Streamlit server process and never block the UI thread.
    global _preload_started
    with _preload_lock:
        if _preload_started:
            return False
        _preload_started = True

    threading.Thread(
        target=preload_ollama_model,
        name="mailmind-ollama-preload",
        daemon=True,
    ).start()
    return True
