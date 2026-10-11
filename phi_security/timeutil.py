import re
from datetime import datetime, timedelta, timezone


def parse_time(value):
    if not isinstance(value, str):
        raise TypeError("time must be a string")
    if value.lower() == "now":
        return datetime.now(timezone.utc)
    match = re.fullmatch(
        r"(\d+)\s*(h|hours?|d|days?|m|minutes?)(?:\s+ago)?", value.lower()
    )
    if match:
        amount = int(match.group(1))
        unit = match.group(2)[0]
        return datetime.now(timezone.utc) - timedelta(
            seconds=amount * {"h": 3600, "d": 86400, "m": 60}[unit]
        )
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result
