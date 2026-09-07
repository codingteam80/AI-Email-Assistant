from __future__ import annotations


UNSAFE_SECURITY_CATEGORIES = {
    "spam",
    "phishing",
    "malware",
    "scam / fraud",
    "impersonation",
    "suspicious",
}

LOW_RISK_SECURITY_CATEGORIES = {
    "safe / misclassified",
    "promotional",
}


def should_contextually_refine_security(
    *,
    category: str,
    source: str,
    security_input_version: int,
    genuine_new: bool = False,
    risk_score: int = 0,
) -> bool:
    """Return whether a full-message row should receive contextual AI review.

    Contextual AI remains the second opinion for deterministic risk candidates.
    Genuinely NEW mail no longer pays the LLM latency when the completed
    deterministic full-message pass is clearly low-risk (Safe/Promotional with
    zero local risk score). Any unsafe/unknown category or a low-risk category
    that still carries deterministic risk points remains eligible for AI review.
    Existing Safe/Promotional mail is not repeatedly reclassified.
    """
    if int(security_input_version or 0) < 2:
        return False
    if str(source or "").strip().casefold() in {"hybrid ai", "user"}:
        return False

    normalized_category = str(category or "").strip().casefold()
    if genuine_new:
        if normalized_category not in LOW_RISK_SECURITY_CATEGORIES:
            return True
        return int(risk_score or 0) > 0
    return normalized_category in UNSAFE_SECURITY_CATEGORIES
