# Normalize provider timestamps into the application's display timezone.
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from config import DISPLAY_TIMEZONE_CACHE_SIZE, EMAIL_DISPLAY_TIMEZONE


@lru_cache(maxsize=DISPLAY_TIMEZONE_CACHE_SIZE)
def display_timezone(name: str | None = None):
    zone_name = str(
        name or EMAIL_DISPLAY_TIMEZONE
    ).strip()
    try:
        return ZoneInfo(zone_name)
    except ZoneInfoNotFoundError:
        if zone_name.casefold() == "asia/manila":
            return timezone(timedelta(hours=8), name="Asia/Manila")
        return timezone.utc


def parse_timestamp(value) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def to_display_datetime(value) -> datetime | None:
    parsed = parse_timestamp(value)
    return parsed.astimezone(display_timezone()) if parsed is not None else None


def format_display_datetime(value, fallback: str = "Unknown") -> str:
    converted = to_display_datetime(value)
    return converted.strftime("%Y-%m-%d %H:%M") if converted else fallback


def display_now() -> datetime:
    return datetime.now(display_timezone())


