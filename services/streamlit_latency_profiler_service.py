# Lightweight server-side latency profiler for Manual Summary in Streamlit.
# Measurement only: this module does not change summary generation behavior.
import json
import os
import statistics
import time
from datetime import datetime

import streamlit as st


_PROFILE_STATE_KEY = "streamlit_summary_latency_profile_active"
_PROFILE_RECORDS_KEY = "streamlit_summary_latency_profile_records"


def _now() -> float:
    return time.perf_counter()


def _results_dir() -> str:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(project_root, "test", "results")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_round(value):
    if value is None:
        return None
    return round(float(value), 4)


def mark_generate_click(selected_count: int, mode: str) -> None:
    st.session_state[_PROFILE_STATE_KEY] = {
        "started_at": _now(),
        "started_wall": datetime.now().isoformat(timespec="seconds"),
        "selected_count": int(selected_count or 0),
        "mode": str(mode or "manual"),
    }


def mark_job_launch(origin: str = "manual") -> None:
    if str(origin or "manual") != "manual":
        return
    active = st.session_state.get(_PROFILE_STATE_KEY)
    if isinstance(active, dict) and "job_launched_at" not in active:
        active["job_launched_at"] = _now()


def mark_future_done(origin: str = "manual") -> None:
    if str(origin or "manual") != "manual":
        return
    active = st.session_state.get(_PROFILE_STATE_KEY)
    if isinstance(active, dict) and "future_done_at" not in active:
        active["future_done_at"] = _now()


def mark_commit_done(origin: str = "manual", summary_count: int = 0) -> None:
    if str(origin or "manual") != "manual":
        return
    active = st.session_state.get(_PROFILE_STATE_KEY)
    if isinstance(active, dict):
        active["commit_done_at"] = _now()
        active["summary_count"] = int(summary_count or 0)


def mark_summary_render_start():
    active = st.session_state.get(_PROFILE_STATE_KEY)
    if not isinstance(active, dict) or "commit_done_at" not in active:
        return None
    return _now()


def mark_summary_render_visible(render_started_at=None) -> dict | None:
    active = st.session_state.get(_PROFILE_STATE_KEY)
    if not isinstance(active, dict) or "commit_done_at" not in active:
        return None

    visible_at = _now()
    started_at = active.get("started_at")
    launched_at = active.get("job_launched_at")
    future_done_at = active.get("future_done_at")
    commit_done_at = active.get("commit_done_at")
    if started_at is None or launched_at is None or future_done_at is None:
        return None

    record = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": active.get("mode", "manual"),
        "selected_count": int(active.get("selected_count") or 0),
        "summary_count": int(active.get("summary_count") or 0),
        "click_to_job_launch_seconds": _safe_round(launched_at - started_at),
        "background_job_seconds": _safe_round(future_done_at - launched_at),
        "commit_seconds": _safe_round(commit_done_at - future_done_at),
        "rerun_to_summary_render_start_seconds": _safe_round(
            (render_started_at - commit_done_at) if render_started_at is not None else None
        ),
        "summary_render_seconds": _safe_round(
            (visible_at - render_started_at) if render_started_at is not None else None
        ),
        "click_to_server_rendered_seconds": _safe_round(visible_at - started_at),
    }

    records = list(st.session_state.get(_PROFILE_RECORDS_KEY, []) or [])
    records.append(record)
    st.session_state[_PROFILE_RECORDS_KEY] = records[-50:]
    st.session_state.pop(_PROFILE_STATE_KEY, None)
    _write_reports(records[-50:])
    print(
        "[Streamlit latency] "
        f"click_to_server_rendered={record['click_to_server_rendered_seconds']:.3f}s "
        f"prep={record['click_to_job_launch_seconds']:.3f}s "
        f"job={record['background_job_seconds']:.3f}s "
        f"commit={record['commit_seconds']:.3f}s "
        f"render={record.get('summary_render_seconds') or 0.0:.3f}s"
    )
    return record


def _metric(values: list[float]) -> dict:
    values = [float(value) for value in values if value is not None]
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * 0.95 + 0.999999)))
    return {
        "count": len(values),
        "average": round(sum(values) / len(values), 4),
        "median": round(statistics.median(values), 4),
        "p95": round(ordered[p95_index], 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def _write_reports(records: list[dict]) -> None:
    try:
        results_dir = _results_dir()
        payload = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "note": "Server-side Streamlit timing. Browser paint/network after server render is not included.",
            "runs": len(records),
            "metrics": {
                key: _metric([row.get(key) for row in records])
                for key in (
                    "click_to_server_rendered_seconds",
                    "click_to_job_launch_seconds",
                    "background_job_seconds",
                    "commit_seconds",
                    "rerun_to_summary_render_start_seconds",
                    "summary_render_seconds",
                )
            },
            "records": records,
        }
        json_path = os.path.join(results_dir, "streamlit_summary_latency_profile_output.json")
        txt_path = os.path.join(results_dir, "streamlit_summary_latency_profile_result.txt")
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        lines = [
            "MailMind Streamlit Summary Latency Profile",
            "=" * 80,
            f"Runs: {len(records)}",
            "Server-side timing only; browser paint/network after server render is not included.",
            "",
        ]
        labels = {
            "click_to_server_rendered_seconds": "Click -> server rendered",
            "click_to_job_launch_seconds": "Click -> job launch",
            "background_job_seconds": "Background summary job",
            "commit_seconds": "Commit / state update",
            "rerun_to_summary_render_start_seconds": "Commit -> Summary render start",
            "summary_render_seconds": "AI Summary workspace render",
        }
        for key, label in labels.items():
            stats = payload["metrics"][key]
            if not stats.get("count"):
                continue
            lines.append(
                f"{label:<32} avg={stats['average']:.3f}s median={stats['median']:.3f}s "
                f"p95={stats['p95']:.3f}s min={stats['min']:.3f}s max={stats['max']:.3f}s"
            )
        lines.extend(["", "RUNS"])
        for index, row in enumerate(records, 1):
            lines.append(
                f"{index:02d}. selected={row['selected_count']} summaries={row['summary_count']} "
                f"total={row['click_to_server_rendered_seconds']:.3f}s "
                f"prep={row['click_to_job_launch_seconds']:.3f}s "
                f"job={row['background_job_seconds']:.3f}s "
                f"commit={row['commit_seconds']:.3f}s "
                f"render={(row.get('summary_render_seconds') or 0.0):.3f}s"
            )
        with open(txt_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except Exception:
        # Profiling must never alter or block the application flow.
        return
