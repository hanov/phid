"""Natural-language intent routing with deterministic, evidence-backed answers."""

import re
from datetime import datetime, timedelta, timezone

from .analysis import READ_EVENTS
from .events import touches, unique_events
from .llm import Router
from .privacy import safe, sensitive


def ask(engine, question, params):
    q = question.lower()
    now = datetime.now(timezone.utc)
    time_range = dict(params.get("timeRange", {}))
    if not time_range and ("yesterday" in q or "today" in q):
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        time_range = {
            "from": (
                midnight - timedelta(days=1) if "yesterday" in q else midnight
            ).isoformat(),
            "to": (midnight if "yesterday" in q else now).isoformat(),
        }
    events = unique_events(engine.filtered(engine.all("evidence"), time_range))
    resources = engine.all("resources")
    # Resolve user-supplied known identifiers; never derive AWS actions from untrusted content.
    targets = [
        r
        for r in resources
        if r["name"].lower() in q or r["arn"].lower() in q or r["id"].lower() in q
    ]
    if "phi" in q or "patient" in q:
        targets = targets or [
            r for r in resources if r["classification"].startswith("PHI")
        ]
    elif "pii" in q:
        targets = targets or [r for r in resources if r["classification"] == "PII"]
    else:
        targets = targets or [r for r in resources if sensitive(r)]
    selected = [e for e in events if any(touches(e, r["arn"]) for r in targets)]
    intent = "search"
    answer = None
    records = []
    if any(
        term in q
        for term in ["decrypt", "can access", "can read", "can write", "can export"]
    ):
        intent = "candidate_access"
        principals = engine.all("principals")
        records = [
            p
            for p in principals
            if set(p.get("candidateResources", [])) & {r["id"] for r in targets}
        ]
        if "decrypt" in q:
            key_ids = {r.get("encryption", {}).get("keyId") for r in targets} - {None}
            keys = [
                r
                for r in resources
                if r["type"] == "KMS" and (r["arn"] in key_ids or r["name"] in key_ids)
            ]
            records = [
                p
                for p in principals
                if any(
                    k["id"] in p.get("accessByCapability", {}).get("decrypt", [])
                    for k in keys
                )
            ]
        if "application" in q:
            arns = {p["arn"] for p in records}
            workload_arns = {
                e["to"]
                for e in engine.all("edges")
                if e["from"] in arns
                and e.get("relation") in ["execution_role", "instance_profile"]
            }
            records = [r for r in resources if r["arn"] in workload_arns]
        answer = f"{len(records)} candidate principals found; effective authorization requires policy and condition review."
    elif any(
        term in q for term in ["who accessed", "who read", "download", "accessed by"]
    ):
        intent = "observed_access"
        records = [
            e
            for e in selected
            if e.get("eventType") in READ_EVENTS and e.get("successful")
        ]
        answer = f"{len(records)} unique successful read events by {len({e.get('identity') for e in records if e.get('identity')})} identities in collected evidence."
    elif any(term in q for term in ["logs", "logged", "logging"]):
        intent = "log_leakage"
        records = [e for e in selected if e.get("eventType") == "SensitiveLogEntry"]
        answer = f"{len(records)} sensitive log events in collected evidence."
    elif any(
        term in q for term in ["leave", "exfiltrat", "transfer", "outside", "boundary"]
    ):
        intent = "movement"
        records = [
            f
            for f in engine.all("findings")
            if f.get("assessment") in ["possible_exfiltration", "suspected_exposure"]
            and f.get("resourceId") in {r["id"] for r in targets}
            and set(f.get("evidence", [])) & {e["id"] for e in events}
        ]
        answer = f"{len(records)} correlated movement/exposure findings. These do not prove that PHI left a VPC or establish unauthorized disclosure."
    elif any(term in q for term in ["where", "exists", "exist", "located"]):
        intent = "inventory"
        records = targets
        answer = f"{len(records)} sensitive-data candidates in the stored inventory; review classificationBasis."
    words = set(re.findall(r"[a-z0-9_-]+", q))
    matches = []
    for kind in ["resources", "findings", "evidence", "incidents"]:
        for row in engine.all(kind):
            score = sum(word in str(row).lower() for word in words)
            if score:
                matches.append({"kind": kind, "score": score, "record": safe(row)})
    matches.sort(key=lambda row: row["score"], reverse=True)
    result = {
        "mode": "evidence-backed-question",
        "intent": intent,
        "question": safe(question),
        "answer": answer
        or "Matching stored records are listed; no unsupported conclusion was inferred.",
        "records": records,
        "evidenceIds": sorted({e["id"] for e in selected}),
        "timeRange": time_range,
        "total": len(matches),
        "matches": matches[: params.get("limit", 20)],
        "coverage": engine.store.meta("lastScan"),
    }
    if engine.config.get("llm", {}).get("provider", "none") != "none":
        result["modelCommentary"] = Router(engine.config, engine.store).query(
            question, selected
        )
    return result
