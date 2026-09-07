from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class SecurityRuleHit:
    """One explainable deterministic security-rule contribution."""

    rule_id: str
    points: int
    reason: str
    categories: Tuple[str, ...]
    strong_flag: str = ""
