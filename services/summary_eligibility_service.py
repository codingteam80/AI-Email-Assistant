# Provider-neutral source of truth for deciding whether an email may generate a
# new AI summary. This service is intentionally independent from Streamlit so
# Auto/Manual and Individual/Batch flows can share the exact same rules.
from dataclasses import dataclass


SAFE_CATEGORY = "Safe / Misclassified"
PROMOTIONAL_CATEGORY = "Promotional"
SUMMARIZABLE_CATEGORIES = {SAFE_CATEGORY, PROMOTIONAL_CATEGORY}
UNSAFE_CATEGORIES = {
    "Spam",
    "Phishing",
    "Malware",
    "Scam / Fraud",
    "Impersonation",
    "Suspicious",
}

ACTION_GENERATE = "generate"
ACTION_REUSE_EXISTING = "reuse_existing"
ACTION_WAIT_FOR_SECURITY = "wait_for_security"
ACTION_BLOCKED_SECURITY = "blocked_security"
ACTION_BLOCKED_PROVIDER_SPAM = "blocked_provider_spam"
ACTION_BLOCKED_UNAVAILABLE = "blocked_unavailable"

_LIFECYCLE_ALIASES = {
    "new": "NEW",
    "restored": "RESTORED",
    "restore": "RESTORED",
    "moved_spam_to_inbox": "MOVED_SPAM_TO_INBOX",
    "spam_to_inbox": "MOVED_SPAM_TO_INBOX",
    "moved_to_inbox": "MOVED_SPAM_TO_INBOX",
    "existing": "EXISTING",
}
_PENDING_SECURITY_CATEGORIES = {
    "",
    "unclassified",
    "pending",
    "unknown",
    "none",
}


@dataclass(frozen=True)
class SummaryEligibility:
    # ``can_generate`` means a brand-new summary may be created now.
    can_generate: bool
    action: str
    reason: str
    security_category: str
    provider_spam: bool
    lifecycle_state: str
    already_summarized: bool

    @property
    def should_reuse_existing(self) -> bool:
        return self.action == ACTION_REUSE_EXISTING

    @property
    def waiting_for_security(self) -> bool:
        return self.action == ACTION_WAIT_FOR_SECURITY


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "on"}
    return bool(value)


def normalize_lifecycle_state(value) -> str:
    key = str(value or "existing").strip().casefold().replace("-", "_").replace(" ", "_")
    return _LIFECYCLE_ALIASES.get(key, str(value or "EXISTING").strip().upper())


def evaluate_summary_eligibility(
    email_data: dict,
    *,
    lifecycle_state: str = "EXISTING",
    already_summarized: bool = False,
) -> SummaryEligibility:
    # Final rule shared by every summary mode:
    #   1. Security must have a final verdict first.
    #   2. Safe / Misclassified and ordinary Promotional mail in the CURRENT
    #      provider Inbox are eligible. ``provider_spam`` is the normalized
    #      provider-location flag.
    #   3. Existing summaries are reused/relinked instead of duplicated.
    #   4. Lifecycle labels never bypass Security. RESTORED can still be manually
    #      summarized when eligible, but mailbox orchestration does not treat a
    #      restoration itself as a NEW/Auto-Summary arrival.
    item = dict(email_data or {})
    lifecycle = normalize_lifecycle_state(lifecycle_state)
    category = str(item.get("security_category") or "").strip()
    category_key = category.casefold()
    provider_spam = _as_bool(item.get("provider_spam"))
    remote_available = _as_bool(item.get("remote_available", True))
    summarized = bool(already_summarized)

    if not remote_available:
        return SummaryEligibility(
            False,
            ACTION_BLOCKED_UNAVAILABLE,
            "The original email is not currently available in the provider mailbox.",
            category,
            provider_spam,
            lifecycle,
            summarized,
        )

    if category_key in _PENDING_SECURITY_CATEGORIES:
        return SummaryEligibility(
            False,
            ACTION_WAIT_FOR_SECURITY,
            "Security classification must finish before summary eligibility is decided.",
            category or "Unclassified",
            provider_spam,
            lifecycle,
            summarized,
        )

    if category not in SUMMARIZABLE_CATEGORIES:
        return SummaryEligibility(
            False,
            ACTION_BLOCKED_SECURITY,
            f"MailMind security classified this email as {category}; it is not eligible for summarization.",
            category,
            provider_spam,
            lifecycle,
            summarized,
        )

    if provider_spam:
        return SummaryEligibility(
            False,
            ACTION_BLOCKED_PROVIDER_SPAM,
            "The email is still in the provider Spam/Junk location, so summarization remains blocked until it is restored to Inbox.",
            category,
            True,
            lifecycle,
            summarized,
        )

    if summarized:
        return SummaryEligibility(
            False,
            ACTION_REUSE_EXISTING,
            "This email is already represented by an existing summary; reuse or relink it instead of creating a duplicate.",
            category,
            False,
            lifecycle,
            True,
        )

    return SummaryEligibility(
        True,
        ACTION_GENERATE,
        "The email is eligible for summarization and its current provider location is Inbox.",
        category,
        False,
        lifecycle,
        False,
    )
