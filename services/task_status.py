# Canonical task-status definitions shared by summaries and the To-Do workspace.
from __future__ import annotations

TASK_STATUSES = (
    "Not Started",
    "In Progress",
    "On Hold",
    "Completed",
    "Cancelled",
)

CLOSED_TASK_STATUSES = frozenset({"Completed", "Cancelled"})

_STATUS_ALIASES = {
    "not started": "Not Started",
    "not-started": "Not Started",
    "pending": "Not Started",
    "new": "Not Started",
    "to do": "Not Started",
    "todo": "Not Started",
    "in progress": "In Progress",
    "in-progress": "In Progress",
    "in_progress": "In Progress",
    "ongoing": "In Progress",
    "started": "In Progress",
    "on hold": "On Hold",
    "on-hold": "On Hold",
    "on_hold": "On Hold",
    "hold": "On Hold",
    "paused": "On Hold",
    "waiting": "On Hold",
    "blocked": "On Hold",
    "complete": "Completed",
    "completed": "Completed",
    "done": "Completed",
    "finished": "Completed",
    "cancelled": "Cancelled",
    "canceled": "Cancelled",
    "cancel": "Cancelled",
}

def normalize_task_status(value) -> str:
    # Return one of the five canonical task-status labels.
    #
    # Older stored values (Pending/Complete) are intentionally mapped forward so
    # existing databases keep working without a destructive migration.
    key = str(value or "Not Started").strip().casefold().replace("_", " ")
    return _STATUS_ALIASES.get(key, "Not Started")

def task_status_slug(value) -> str:
    return normalize_task_status(value).casefold().replace(" ", "-")

def task_status_filter_key(value) -> str:
    return normalize_task_status(value).casefold().replace(" ", "_")

def aggregate_task_status(values) -> str:
    # Choose a useful single status for a batch containing multiple tasks.
    statuses = [normalize_task_status(value) for value in values]
    if not statuses:
        return "Not Started"
    if all(status == "Cancelled" for status in statuses):
        return "Cancelled"
    if all(status in CLOSED_TASK_STATUSES for status in statuses):
        return "Completed" if "Completed" in statuses else "Cancelled"
    if "In Progress" in statuses:
        return "In Progress"
    if "On Hold" in statuses:
        return "On Hold"
    if "Not Started" in statuses:
        return "Not Started"
    return "Completed"
