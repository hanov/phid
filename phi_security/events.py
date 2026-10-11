"""Canonical matching and event counting shared by collection and analysis."""

import re


def canonical_resource(value):
    if value and value.startswith("s3://"):
        return "arn:aws:s3:::" + value[5:].rstrip("/")
    return value


def resource_matches(selector, resource):
    selector = canonical_resource(selector)
    return any(
        selector == value or selector in value
        for value in [
            resource.get("id", ""),
            resource.get("arn", ""),
            resource.get("name", ""),
        ]
    )


def event_resources(event):
    return list(
        dict.fromkeys(
            [r for r in [event.get("resource"), *event.get("resources", [])] if r]
        )
    )


def touches(event, arn):
    return any(r == arn or r.startswith(arn + "/") for r in event_resources(event))


def unique_events(events):
    """Collapse current and legacy CloudTrail rows while retaining resource links."""
    grouped = {}
    for event in events:
        legacy = (
            re.match(
                r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:arn:|None|$)",
                str(event.get("reference", "")),
            )
            if event.get("source") == "cloudtrail"
            else None
        )
        key = (
            event.get("source"),
            event.get("sourceEventId") or (legacy.group(1) if legacy else event["id"]),
        )
        if key not in grouped:
            grouped[key] = dict(event)
        else:
            grouped[key]["resources"] = list(
                dict.fromkeys(event_resources(grouped[key]) + event_resources(event))
            )
    return list(grouped.values())
