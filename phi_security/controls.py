"""Technical control observations, not legal compliance determinations."""

from .privacy import sensitive

CONTROL_TYPES = {
    "PUBLIC_SENSITIVE_DATA": ["access_control"],
    "RESOURCE_POLICY_EXTERNAL_ACCESS": ["access_control", "least_privilege"],
    "EXCESSIVE_ACCESS": ["least_privilege"],
    "UNENCRYPTED_SENSITIVE_DATA": ["encryption_at_rest"],
    "OPEN_SECURITY_GROUP": ["network_access_control"],
    "SENSITIVE_DATA_IN_LOGS": ["data_minimization", "logging"],
    "SENSITIVE_HTTP_PAYLOAD_LOGGING": ["data_minimization", "logging"],
    "SENSITIVE_RETENTION": ["retention"],
    "AUDIT_LOGGING_GAP": ["audit_controls"],
    "TRANSPORT_SECURITY_GAP": ["transmission_security"],
    "MFA_ACCESS_GAP": ["authentication"],
    "INTEGRITY_CONTROL_GAP": ["integrity"],
}


def assess(resources, findings, evidence):
    checks = []
    for r in resources:
        if not sensitive(r):
            continue
        refs = r.get("evidence", [])
        checks.append(
            {
                "resourceId": r["id"],
                "control": "encryption_at_rest",
                "status": "GAP"
                if r.get("encryption", {}).get("type") == "none"
                else "UNKNOWN"
                if r.get("encryption", {}).get("type") in [None, "unknown"]
                else "OBSERVED",
                "evidence": refs,
            }
        )
        if r["type"] == "S3":
            logging = r.get("logging")
            trails = [e for e in evidence if e.get("eventType") == "TelemetryCoverage"]
            status = (
                "OBSERVED"
                if logging and logging.get("LoggingEnabled")
                else "REVIEW"
                if trails
                else "UNKNOWN"
            )
            checks.append(
                {
                    "resourceId": r["id"],
                    "control": "audit_controls",
                    "status": status,
                    "evidence": refs + [e["id"] for e in trails],
                    "note": "Trail presence does not establish that this bucket has data events enabled.",
                }
            )
            versioning = r.get("versioning")
            checks.append(
                {
                    "resourceId": r["id"],
                    "control": "integrity_recovery",
                    "status": "OBSERVED"
                    if versioning and versioning.get("Status") == "Enabled"
                    else "REVIEW"
                    if versioning is not None
                    else "UNKNOWN",
                    "evidence": refs,
                    "note": "Versioning is one recovery control, not proof of integrity.",
                }
            )
        tls = [
            e
            for e in evidence
            if e.get("resource") == r["arn"]
            and e.get("eventType") == "ListenerObserved"
        ]
        if tls:
            checks.append(
                {
                    "resourceId": r["id"],
                    "control": "transmission_security",
                    "status": "REVIEW"
                    if any(e.get("protocol") in ["HTTP", "TCP"] for e in tls)
                    else "OBSERVED",
                    "evidence": [e["id"] for e in tls],
                    "note": "Listener protocol observed; application redirects and backend encryption require verification.",
                }
            )
        if r["type"] == "S3":
            statements = r.get("policy", {}).get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            enforced = [
                stmt
                for stmt in statements
                if stmt.get("Effect") == "Deny"
                and str(
                    stmt.get("Condition", {})
                    .get("Bool", {})
                    .get("aws:SecureTransport", "")
                ).lower()
                == "false"
            ]
            checks.append(
                {
                    "resourceId": r["id"],
                    "control": "transmission_security",
                    "status": "OBSERVED" if enforced else "REVIEW",
                    "evidence": refs,
                    "note": "Bucket policy transport restriction; evaluate principal/action/resource scope.",
                }
            )
        for control in ["authentication", "incident_visibility"]:
            checks.append(
                {
                    "resourceId": r["id"],
                    "control": control,
                    "status": "UNKNOWN",
                    "evidence": refs,
                    "note": "Requires workload-specific verification.",
                }
            )
    for f in findings:
        for kind, controls in CONTROL_TYPES.items():
            if f.get("type", "").startswith(kind):
                for control in controls:
                    checks.append(
                        {
                            "resourceId": f["resourceId"],
                            "control": control,
                            "status": "REVIEW"
                            if f.get("status") == "RESOLVED"
                            else "GAP",
                            "evidence": f.get("evidence", []),
                            "findingId": f["id"],
                        }
                    )
    return {
        "checks": checks,
        "summary": {
            status: sum(c["status"] == status for c in checks)
            for status in ["GAP", "REVIEW", "UNKNOWN", "OBSERVED"]
        },
        "assessment": "Technical observations only. No legal compliance or non-compliance determination.",
    }
