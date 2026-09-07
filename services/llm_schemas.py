# JSON schemas for Ollama structured-output calls.

_STRING_ARRAY = {
    "type": "array",
    "items": {"type": "string"},
}

ACTION_AUDIT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action_items": _STRING_ARRAY,
    },
    "required": ["action_items"],
}

SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "task_title": {"type": "string"},
        "key_points": _STRING_ARRAY,
        "deadlines": _STRING_ARRAY,
        "action_items": _STRING_ARRAY,
        "action_item_details": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "action": {"type": "string"},
                    "due_date": {"type": "string"},
                },
                "required": ["action", "due_date"],
            },
        },
    },
    "required": [
        "summary",
        "task_title",
        "key_points",
        "deadlines",
        "action_items",
        "action_item_details",
    ],
}

SECURITY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "category": {"type": "string"},
        "confidence": {"type": "integer"},
        "reasons": _STRING_ARRAY,
        "malicious": {"type": "boolean"},
    },
    "required": ["category", "confidence", "reasons", "malicious"],
}

SECURITY_BATCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "uid": {"type": "string"},
                    "category": {"type": "string"},
                    "confidence": {"type": "integer"},
                    "reasons": _STRING_ARRAY,
                    "malicious": {"type": "boolean"},
                },
                "required": ["uid", "category", "confidence", "reasons", "malicious"],
            },
        },
    },
    "required": ["results"],
}

INCREMENTAL_SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "priority": {
            "type": "string",
            "enum": ["Critical", "High", "Medium", "Low"],
        },
        "key_points": _STRING_ARRAY,
        "deadlines": _STRING_ARRAY,
        "task_updates": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "previous_index": {"type": ["integer", "null"]},
                    "state": {
                        "type": "string",
                        "enum": ["unchanged", "updated", "completed", "cancelled", "new", "reopened"],
                    },
                    "action": {"type": "string"},
                    "due_date": {"type": "string"},
                    "due_date_changed": {"type": "boolean"},
                },
                "required": [
                    "previous_index",
                    "state",
                    "action",
                    "due_date",
                    "due_date_changed",
                ],
            },
        },
    },
    "required": [
        "summary",
        "priority",
        "key_points",
        "deadlines",
        "task_updates",
    ],
}

BATCH_SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "key_takeaways": _STRING_ARRAY,
        "action_items": _STRING_ARRAY,
    },
    "required": ["title", "summary", "key_takeaways", "action_items"],
}
