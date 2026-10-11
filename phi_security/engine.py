import ipaddress
import logging
import time
import uuid
from datetime import datetime

from .analysis import RANK, READ_EVENTS, analyze, baseline
from .collect import Collector
from .config import load
from .events import canonical_resource, resource_matches, touches, unique_events
from .privacy import fingerprint, safe, sensitive
from .storage import Store, now
from .timeutil import parse_time

logger = logging.getLogger("phid")


class APIError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _check_unexpected_ip(ip_str, approved_networks):
    """Return True if ip_str is a globally-routable address outside all approved networks."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global and not any(addr in net for net in approved_networks)
    except (ValueError, TypeError):
        return False


def _hypotheses(events, config, account_id):
    """Generate investigation hypotheses from collected evidence.

    Each hypothesis may be UNRESOLVED or INSUFFICIENT_EVIDENCE.
    Returns a non-empty list; the generic fallback is only added when no
    specific pattern is triggered.
    """
    reads = [
        e
        for e in events
        if e.get("source") == "cloudtrail"
        and e.get("eventType") in READ_EVENTS
        and e.get("successful")
    ]
    denied = [
        e
        for e in events
        if e.get("source") == "cloudtrail" and e.get("successful") is False
    ]
    h = []

    # Bulk read hypothesis — triggered when collected read volume exceeds the threshold.
    if len(reads) >= config.get("bulk_threshold", 1000):
        h.append(
            {
                "id": "bulk_reads",
                "title": "Unusually high volume of sensitive-data reads in collected window",
                "status": "UNRESOLVED",
                "supportingEvidence": [e["id"] for e in reads[:100]],
                "contradictingEvidence": [],
                "missingEvidence": [
                    "Confirm whether a scheduled migration, backup, or approved bulk export was running",
                    "Verify business authorization for this access volume",
                ],
            }
        )

    # Unexpected source IP hypothesis.
    try:
        approved = [ipaddress.ip_network(c) for c in config.get("approved_cidrs", [])]
        unexpected = [
            e
            for e in reads
            if e.get("sourceIp") and _check_unexpected_ip(e["sourceIp"], approved)
        ]
        if unexpected:
            h.append(
                {
                    "id": "unexpected_ip",
                    "title": "Access from IP addresses outside configured approved ranges",
                    "status": "UNRESOLVED",
                    "supportingEvidence": [e["id"] for e in unexpected[:50]],
                    "contradictingEvidence": [],
                    "missingEvidence": [
                        "Verify whether the IP belongs to a corporate VPN, approved service, or expected partner",
                        "Check whether the identity was travelling or using a new network provider",
                    ],
                }
            )
    except (ValueError, TypeError):
        pass

    # Cross-account destination hypothesis.
    if account_id:
        cross = [
            e
            for e in reads
            if e.get("destinationAccount") and e["destinationAccount"] != account_id
        ]
        if cross:
            h.append(
                {
                    "id": "cross_account",
                    "title": "Sensitive-data access involving a cross-account destination",
                    "status": "UNRESOLVED",
                    "supportingEvidence": [e["id"] for e in cross],
                    "contradictingEvidence": [],
                    "missingEvidence": [
                        "Verify destination account ownership and business authorization",
                        "Check for approved data sharing or migration agreements",
                    ],
                }
            )

    # Fallback — generic hypothesis when no specific pattern was triggered.
    if not h:
        h.append(
            {
                "id": "unexpected_access",
                "title": "Access may be outside intended operational scope",
                "status": "UNRESOLVED" if reads else "INSUFFICIENT_EVIDENCE",
                "supportingEvidence": [e["id"] for e in reads],
                "contradictingEvidence": [e["id"] for e in denied],
                "missingEvidence": [
                    "Validate session owner and approved activity",
                    "Verify effective permissions and data sensitivity",
                    "Correlate network destination ownership and data events",
                ],
            }
        )
    return h


def counts(items, key):
    out = {}
    for item in items:
        value = item.get(key, "UNKNOWN")
        out[value] = out.get(value, 0) + 1
    return out


class Engine:
    def __init__(self, config=None, collector=None):
        self.config = config or load()
        self.store = Store(self.config["db"])
        self.collector = collector

    def all(self, kind):
        return self.store.all(kind)

    def find(self, kind, identifier):
        result = self.store.get(kind, identifier)
        if not result:
            result = next(
                (
                    r
                    for r in self.all(kind)
                    if identifier in [r.get("name"), r.get("arn")]
                ),
                None,
            )
        if not result:
            raise APIError(kind + " not found", 404)
        return result

    def filtered(self, items, params):
        for key in [
            "classification",
            "riskLevel",
            "type",
            "severity",
            "status",
            "source",
            "incidentId",
            "investigationId",
            "logGroup",
        ]:
            if params.get(key):
                items = [
                    x
                    for x in items
                    if str(x.get(key, "")).lower() == str(params[key]).lower()
                ]
        for key in ["from", "to"]:
            if params.get(key):
                try:
                    stamp = parse_time(params[key]).timestamp()
                except (ValueError, TypeError):
                    raise APIError("Invalid " + key + " date")

                def keep(x, _key=key, _stamp=stamp):
                    value = x.get(
                        "timestamp", x.get("createdAt", x.get("lastDetected"))
                    )
                    if not value:
                        return False
                    t = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                    return t >= _stamp if _key == "from" else t <= _stamp

                items = [x for x in items if keep(x)]
        return items

    def summary(self, resources):
        return {
            "total": len(resources),
            "byClassification": counts(resources, "classification"),
            "byRisk": counts(resources, "riskLevel"),
            "byType": counts(resources, "type"),
            "withPhi": sum(r["classification"].startswith("PHI") for r in resources),
            "withPii": sum(r["classification"] == "PII" for r in resources),
            "publiclyExposed": sum(r.get("publicAccess") is True for r in resources),
            "unencrypted": sum(
                r.get("encryption", {}).get("type") == "none" for r in resources
            ),
        }

    def scan(self, params, scope="all"):
        if scope not in ["all", "s3", "logs", "databases", "investigation"]:
            raise APIError("Unknown scan scope")
        config = dict(self.config)
        if "regions" in params:
            import re

            if (
                not isinstance(params["regions"], list)
                or not params["regions"]
                or not all(
                    isinstance(x, str)
                    and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", x)
                    for x in params["regions"]
                )
            ):
                raise APIError("regions must contain valid AWS region names")
            config["regions"] = params["regions"]
        if (
            params.get("identity")
            and isinstance(params["identity"], str)
            and not params["identity"].startswith("arn:")
        ):
            config["lookup_username"] = params["identity"]
        if "patterns" in params:
            if not isinstance(params["patterns"], list) or not all(
                isinstance(x, str) for x in params["patterns"]
            ):
                raise APIError("patterns must be a list of detection type names")
            config["requested_patterns"] = params["patterns"]
        if "resource" in params and not isinstance(params["resource"], str):
            raise APIError("resource must be a string")
        if "logGroups" in params:
            if not isinstance(params["logGroups"], list) or not all(
                isinstance(x, str) for x in params["logGroups"]
            ):
                raise APIError("logGroups must be a list")
            config["log_groups"] = params["logGroups"]
        db = self.store.db
        db.execute("BEGIN IMMEDIATE")
        lock = db.execute(
            "SELECT expires FROM locks WHERE name=?", ("scan",)
        ).fetchone()
        if lock and lock[0] > time.time():
            db.rollback()
            raise APIError("A scan is already running", 409)
        db.execute(
            "INSERT OR REPLACE INTO locks VALUES (?,?)",
            ("scan", time.time() + config["max_scan_seconds"] + 120),
        )
        db.commit()
        started = now()
        scan_id = "scan-" + uuid.uuid4().hex
        logger.info("scan  scope=%s  db=%s", scope, config.get("db", ""))
        try:
            collector = self.collector or Collector(config)
            if params.get("timeRange"):
                tr = params["timeRange"]
                if isinstance(tr, str):
                    tr = {"from": tr}
                params = {**params, "timeRange": tr}
                try:
                    collector.start = parse_time(tr["from"])
                    collector.end = parse_time(tr.get("to", "now"))
                    if (
                        collector.start.tzinfo is None
                        or collector.end.tzinfo is None
                        or collector.start >= collector.end
                        or (collector.end - collector.start).days > 90
                    ):
                        raise ValueError()
                except (KeyError, ValueError, TypeError):
                    raise APIError(
                        "timeRange requires timezone-aware from/to, at most 90 days"
                    )
            data = collector.collect(scope, params.get("resource"))
            logger.info(
                "collected  resources=%d  evidence=%d  account=%s",
                len(data["resources"]),
                len(data["evidence"]),
                data["account"],
            )
            account = self.store.meta("account")
            if account and account != data["account"]:
                raise APIError(
                    "Database belongs to another AWS account; select a separate PHI_DB",
                    409,
                )
            db.execute("BEGIN IMMEDIATE")
            self.store.meta("account", data["account"])
            previous_principals = self.all("principals")
            previous_resources = self.all("resources")
            for kind, key in [
                ("resources", "resources"),
                ("principals", "principals"),
                ("evidence", "evidence"),
                ("edges", "edges"),
            ]:
                for item in data[key]:
                    self.store.put(kind, item)
            resources = self.all("resources")
            principals = self.all("principals")
            evidence = unique_events(self.all("evidence"))
            findings, incidents, baselines = analyze(
                resources,
                principals,
                evidence,
                config,
                self.all("findings"),
                self.all("incidents"),
            )
            logger.info(
                "analysis  findings=%d  incidents=%d  baselines=%d",
                len(findings),
                len(incidents),
                len(baselines),
            )
            from .changes import detect as permission_changes

            findings.extend(
                permission_changes(
                    resources,
                    principals,
                    previous_principals,
                    previous_resources,
                    config,
                )
            )
            for finding in findings:
                if finding["type"] in [
                    "SENSITIVE_DATA_IN_LOGS",
                    "SENSITIVE_HTTP_PAYLOAD_LOGGING",
                ]:
                    finding["applicationComponents"] = [
                        edge["from"]
                        for edge in self.all("edges")
                        if edge.get("relation") == "writes_logs"
                        and edge["to"] == finding["resource"]
                    ]
                    finding["candidateLogReaders"] = [
                        p["arn"]
                        for p in principals
                        if finding["resourceId"] in p.get("candidateResources", [])
                    ]
                    resource = next(
                        (r for r in resources if r["id"] == finding["resourceId"]), {}
                    )
                    finding["logRetentionDays"] = resource.get("retentionDays")
                    finding["recommendations"] = [
                        "Disable raw request/response-body logging in the producing application.",
                        "Redact sensitive fields before logging.",
                        "Review log-reader permissions and retention with the privacy team.",
                    ]
            from .lifecycle import reconcile

            resolved = reconcile(
                self.store, findings, data["resources"], data["coverage"]
            )
            for kind, rows in [
                ("resources", resources),
                ("principals", principals),
                ("findings", findings),
                ("incidents", incidents),
                ("baselines", baselines),
            ]:
                for row in rows:
                    self.store.put(kind, row)
            selected = [
                r for r in resources if r["id"] in {x["id"] for x in data["resources"]}
            ]
            if params.get("resource"):
                selected = [
                    r for r in selected if resource_matches(params["resource"], r)
                ]
            selected = self.filtered(selected, params)
            missing = [c for c in data["coverage"] if c["status"] != "COLLECTED"]
            report = {
                "id": scan_id,
                "scanId": scan_id,
                "status": "PARTIAL" if missing else "COMPLETED",
                "scanType": scope.upper(),
                "startedAt": started,
                "completedAt": now(),
                "account": data["account"],
                "filters": params,
                "resources": selected,
                "findings": [
                    f
                    for f in findings
                    if f["resourceId"] in {r["id"] for r in selected}
                ],
                "summary": self.summary(selected),
                "coverage": data["coverage"],
                "eventsScanned": data["eventsScanned"],
            }
            report["summary"]["findingsCount"] = len(report["findings"])
            report["resolvedFindings"] = resolved
            logger.info(
                "%s  %s  resources=%d  findings=%d",
                report["status"],
                report["scanId"],
                len(selected),
                len(report["findings"]),
            )
            if scope == "s3":
                report.update(
                    buckets=selected,
                    totalBuckets=len(selected),
                    bucketsWithPhi=sum(
                        r["classification"].startswith("PHI") for r in selected
                    ),
                    publicBuckets=sum(r.get("publicAccess") is True for r in selected),
                    encryptionSummary=counts(
                        [{"encryption": r["encryption"]["type"]} for r in selected],
                        "encryption",
                    ),
                )
            if scope == "databases":
                report.update(
                    databases=selected,
                    totalDatabases=len(selected),
                    schemaAnalysis={
                        "note": "Metadata only; schema evidence requires a populated Glue catalog."
                    },
                )
            if scope == "logs":
                report.update(
                    logGroupsScanned=len(selected),
                    totalLogEntriesScanned=data["eventsScanned"],
                    logEntriesWithPhi=sum(
                        f.get("matchCount", 0) for f in report["findings"]
                    ),
                )
            self.store.put("scans", report)
            self.store.meta(
                "lastScan",
                {
                    "scanId": scan_id,
                    "status": report["status"],
                    "completedAt": report["completedAt"],
                    "coverage": data["coverage"],
                },
            )
            self.store.prune(config["retention_days"])
            self.store.commit()
            return report
        except Exception:
            db.rollback()
            raise
        finally:
            db.execute("DELETE FROM locks WHERE name=?", ("scan",))
            db.commit()

    def investigate(self, params):
        if not any(params.get(k) for k in ["identity", "resource", "trigger"]):
            raise APIError("identity, resource or trigger is required")
        for field in ["identity", "resource", "trigger"]:
            if params.get(field) and (
                not isinstance(params[field], str) or len(params[field]) > 2000
            ):
                raise APIError(field + " must be a string of at most 2,000 characters")
        logger.info(
            "investigate  %s",
            "  ".join(
                f"{k}={v}"
                for k, v in params.items()
                if k in ("identity", "resource", "trigger") and v
            ),
        )
        refresh = None
        if params.get("refresh", True) and (
            params.get("identity") or params.get("resource")
        ):
            refresh = self.scan(params, "investigation")
        time_range = params.get("timeRange", {})
        if isinstance(time_range, str):
            time_range = {"from": time_range}
        events = self.filtered(self.all("evidence"), time_range)
        for field in ["identity", "resource"]:
            if params.get(field):
                if not isinstance(params[field], str):
                    raise APIError(field + " must be a string")
                events = [
                    e
                    for e in events
                    if (
                        canonical_resource(params[field])
                        if field == "resource"
                        else params[field]
                    )
                    in str(e.get(field) or "")
                ]
        if not params.get("identity") and not params.get("resource"):
            trigger = params.get("trigger")
            matched = self.store.get("findings", trigger) or self.store.get(
                "incidents", trigger
            )
            events = [
                e for e in events if matched and e["id"] in matched.get("evidence", [])
            ]
        from .investigation import review

        review_result = review(self, params, events)
        events = review_result.pop("events")
        reads = [
            e
            for e in events
            if e.get("source") == "cloudtrail"
            and e.get("eventType") in READ_EVENTS
            and e.get("successful")
        ]
        hypotheses = _hypotheses(events, self.config, self.store.meta("account"))
        item = {
            "id": "inv-" + uuid.uuid4().hex,
            "title": "Evidence review",
            "status": "COMPLETED",
            "startedAt": now(),
            "updatedAt": now(),
            "criteria": safe(params),
            "evidence": [e["id"] for e in events],
            "timeline": [
                {"time": e["timestamp"], "event": e["eventType"], "evidenceId": e["id"]}
                for e in sorted(events, key=lambda e: e["timestamp"])
            ],
            "hypotheses": hypotheses,
            "conclusion": {
                "assessment": "confirmed_access" if reads else "insufficient_evidence",
                "summary": "Successful access events were observed; authorization and exposure require human review."
                if reads
                else "Collected evidence does not establish sensitive-data access.",
                "confidence": None,
                "confirmedBreach": False,
            },
            "coverage": self.store.meta("lastScan"),
            "refreshScanId": refresh["scanId"] if refresh else None,
        }
        item.update(review_result)
        item["conclusion"]["disposition"] = review_result["disposition"]
        for hypothesis in item["hypotheses"]:
            hypothesis["contradictingEvidence"] = review_result["contradictingEvidence"]
        if self.config.get("llm", {}).get("provider", "none") != "none":
            from .llm import Router

            item["modelCommentary"] = Router(self.config, self.store).query(
                "Review the evidence and identify alternative explanations.", events
            )
        self.store.put("investigations", item)
        self.store.commit()
        return {
            "investigationId": item["id"],
            "status": item["status"],
            "startedAt": item["startedAt"],
            "existingInvestigation": False,
        }

    def graph(self):
        resources = self.all("resources")
        principals = self.all("principals")
        edges = self.all("edges")
        nodes = [
            {
                "id": r["arn"],
                "resourceId": r["id"],
                "label": r["name"],
                "type": r["type"],
                "classification": r["classification"],
            }
            for r in resources
        ] + [
            {"id": p["arn"], "resourceId": p["id"], "label": p["name"], "type": "IAM"}
            for p in principals
        ]
        for p in principals:
            for r in resources:
                if r["id"] in p.get("candidateResources", []):
                    edges.append(
                        {
                            "id": fingerprint([p["id"], r["id"]])[:24],
                            "from": p["arn"],
                            "to": r["arn"],
                            "relation": "candidate_access",
                            "observedDataMovement": False,
                            "evidence": p.get("evidence", []),
                        }
                    )
        known = {n["id"] for n in nodes}
        for e in edges:
            for key in ["from", "to"]:
                if e[key] not in known:
                    nodes.append(
                        {"id": e[key], "label": e[key], "type": "UnresolvedReference"}
                    )
                    known.add(e[key])
        return {"nodes": nodes, "edges": edges}

    def dispatch(self, method, path, params=None):
        params = params or {}
        parts = [x for x in path.split("/") if x]
        group = parts[0] if parts else "health"
        tail = parts[1:]
        if group == "health":
            return {
                "status": "ok",
                "version": "2.0.0",
                "environment": "live",
                "readOnly": True,
                "account": self.store.meta("account"),
                "lastScan": self.store.meta("lastScan"),
            }
        if group == "scan" and method == "POST":
            return self.scan(params, tail[0] if tail else "all")
        if group == "inventory":
            resources = self.filtered(self.all("resources"), params)
            if tail == ["summary"]:
                return self.summary(resources)
            if tail:
                r = self.find("resources", tail[0])
                r.update(
                    findings=[
                        f for f in self.all("findings") if f["resourceId"] == r["id"]
                    ],
                    evidence=[
                        e for e in self.all("evidence") if e.get("resource") == r["arn"]
                    ],
                    accessingPrincipals=[
                        p
                        for p in self.all("principals")
                        if r["id"] in p.get("resourcesAccessed", [])
                    ],
                    accessHistory=[
                        e
                        for e in self.all("evidence")
                        if e.get("resource") == r["arn"] and e["source"] == "cloudtrail"
                    ],
                )
                return r
            try:
                page = int(params.get("page", 1))
                limit = int(params.get("limit", 20))
            except (ValueError, TypeError):
                raise APIError("Invalid pagination")
            if page < 1 or not 1 <= limit <= 1000:
                raise APIError("page must be positive; limit must be 1–1000")
            start = (page - 1) * limit
            return {
                "data": resources[start : start + limit],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": len(resources),
                    "totalPages": (len(resources) + limit - 1) // limit,
                    "hasNext": start + limit < len(resources),
                    "hasPrev": page > 1,
                },
                "filters": params,
            }
        if group == "findings":
            rows = sorted(
                self.filtered(self.all("findings"), params),
                key=lambda x: RANK.get(x["severity"], 5),
            )
            if tail == ["summary"]:
                return {
                    "total": len(rows),
                    "open": sum(x["status"] == "OPEN" for x in rows),
                    "bySeverity": counts(rows, "severity"),
                    "byType": counts(rows, "type"),
                    "byClassification": counts(rows, "classification"),
                }
            if tail:
                f = self.find("findings", tail[0])
                f["resourceDetails"] = self.store.get("resources", f["resourceId"])
                return f
            return {"total": len(rows), "findings": rows}
        if group == "evidence":
            rows = self.filtered(self.all("evidence"), params)
            if tail and tail[0] == "incident":
                inc = self.find("incidents", tail[1])
                rows = [e for e in rows if e["id"] in inc["evidence"]]
            elif tail:
                return self.find("evidence", tail[0])
            if params.get("investigationId"):
                inv = self.find("investigations", params["investigationId"])
                rows = [e for e in self.all("evidence") if e["id"] in inv["evidence"]]
            if params.get("incidentId"):
                inc = self.find("incidents", params["incidentId"])
                rows = [e for e in self.all("evidence") if e["id"] in inc["evidence"]]
            return {
                "total": len(rows),
                "totalItems": len(rows),
                "evidence": rows,
                "sources": sorted({e["source"] for e in rows}),
            }
        if group == "incidents":
            return self.incident_api(method, tail, params)
        if group == "investigate":
            if method == "POST" and not tail:
                return self.investigate(params)
            if not tail:
                return {
                    "total": len(self.all("investigations")),
                    "investigations": self.all("investigations"),
                }
            inv = self.find("investigations", tail[0])
            if len(tail) == 1:
                return inv
            if tail[1] == "timeline":
                return {
                    "investigationId": inv["id"],
                    "timeline": inv["timeline"],
                    "totalEvents": len(inv["timeline"]),
                }
            if tail[1] == "hypotheses":
                return {
                    "investigationId": inv["id"],
                    "allHypotheses": inv["hypotheses"],
                    "primaryHypothesis": None,
                    "conclusion": inv["conclusion"],
                }
        if group == "data-map":
            return self.graph_api(tail)
        if group == "iam":
            return self.iam_api(tail, params)
        if group == "exposure":
            return self.exposure_api(tail, params)
        if group == "logs":
            return self.logs_api(method, tail, params)
        if group == "baselines":
            rows = self.all("baselines")
            if tail == ["recalculate"] and method == "POST":
                config = dict(self.config)
                days = params.get("days", config["baseline_days"])
                if not isinstance(days, int) or not 2 <= days <= 90:
                    raise APIError("days must be 2–90")
                config["baseline_days"] = days
                principals = self.all("principals")
                if params.get("principalId"):
                    principals = [self.find("principals", params["principalId"])]
                rows = baseline(self.all("evidence"), principals, config)
                for row in rows:
                    self.store.put("baselines", row)
                self.store.commit()
                return {
                    "status": "recalculated",
                    "principals": rows,
                    "updatedAt": now(),
                }
            if tail == ["anomalies"]:
                rows = [b for b in rows if b["status"] == "ANOMALY"]
                return {
                    "total": len(rows),
                    "anomalies": rows,
                    "summary": counts(rows, "status"),
                }
            if tail:
                return self.find("baselines", tail[0])
            return {"total": len(rows), "baselines": rows}
        if group == "context":
            return {
                "resources": [
                    {
                        k: r.get(k)
                        for k in [
                            "id",
                            "type",
                            "classification",
                            "riskLevel",
                            "classificationBasis",
                        ]
                    }
                    for r in self.all("resources")[:100]
                ],
                "findings": [
                    {
                        k: f.get(k)
                        for k in [
                            "id",
                            "resourceId",
                            "severity",
                            "type",
                            "assessment",
                            "evidence",
                        ]
                    }
                    for f in self.all("findings")[:100]
                ],
                "evidence": [
                    {k: e.get(k) for k in ["id", "source", "eventType", "timestamp"]}
                    for e in self.all("evidence")[-100:]
                ],
                "coverage": self.store.meta("lastScan"),
            }
        if group == "agent-cycles":
            rows = self.all("cycles")
            return {"cycles": rows[-100:], "totalCycles": len(rows)}
        if group == "record-cycle" and method == "POST":
            if not isinstance(params.get("cycleId"), str):
                raise APIError("cycleId required")
            item = {**params, "id": params["cycleId"]}
            self.store.put("cycles", item)
            self.store.commit()
            return {"persisted": True}
        raise APIError("Endpoint not found", 404)

    def incident_api(self, method, tail, params):
        if not tail:
            rows = sorted(
                self.filtered(self.all("incidents"), params),
                key=lambda x: RANK.get(x["severity"], 5),
            )
            return {
                "total": len(rows),
                "incidents": rows,
                "summary": {
                    "total": len(rows),
                    "bySeverity": counts(rows, "severity"),
                    **counts(rows, "status"),
                },
            }
        inc = self.find("incidents", tail[0])
        if len(tail) == 1:
            return inc
        if tail[1] == "notes" and method == "POST":
            note = params.get("note")
            if not isinstance(note, str) or not note.strip() or len(note) > 10000:
                raise APIError("Note text is required, maximum 10,000 characters")
            item = {
                "id": "note-" + uuid.uuid4().hex,
                "text": safe(note.strip()),
                "addedAt": now(),
                "addedBy": "local-user",
            }
            inc.setdefault("notes", []).append(item)
            inc["updatedAt"] = now()
            self.store.put("incidents", inc)
            self.store.commit()
            return {
                "incidentId": inc["id"],
                "note": item,
                "totalNotes": len(inc["notes"]),
                "message": "Note persisted",
            }
        if tail[1] == "evidence":
            rows = [e for e in self.all("evidence") if e["id"] in inc["evidence"]]
            return {
                "incidentId": inc["id"],
                "evidence": rows,
                "totalEvidenceItems": len(rows),
                "sources": sorted({e["source"] for e in rows}),
            }
        if tail[1] == "timeline":
            return {
                "incidentId": inc["id"],
                "timeline": inc["timeline"],
                "totalEvents": len(inc["timeline"]),
            }
        raise APIError("Endpoint not found", 404)

    def graph_api(self, tail):
        graph = self.graph()

        def node(identifier):
            result = next(
                (
                    n
                    for n in graph["nodes"]
                    if identifier in [n["id"], n.get("resourceId"), n["label"]]
                ),
                None,
            )
            if not result:
                raise APIError("Resource node not found", 404)
            return result

        if not tail:
            return {
                "graph": graph,
                "meta": {
                    "totalNodes": len(graph["nodes"]),
                    "totalEdges": len(graph["edges"]),
                    "description": "Observed configuration and access relationships; edges are not all data flows.",
                },
            }
        if tail[0] == "resource":
            n = node(tail[1])
            edges = [e for e in graph["edges"] if n["id"] in [e["from"], e["to"]]]
            ids = {e[k] for e in edges for k in ["from", "to"]}
            return {
                "resource": n,
                "subgraph": {
                    "nodes": [x for x in graph["nodes"] if x["id"] in ids or x == n],
                    "edges": edges,
                },
                "upstreamNodes": [
                    x
                    for x in graph["nodes"]
                    if any(e["from"] == x["id"] and e["to"] == n["id"] for e in edges)
                ],
                "downstreamNodes": [
                    x
                    for x in graph["nodes"]
                    if any(e["to"] == x["id"] and e["from"] == n["id"] for e in edges)
                ],
            }
        if tail[0] == "flow":
            start = node(tail[1])
            end = node(tail[2])
            queue = [([start["id"]], [])]
            seen = {start["id"]}
            while queue:
                ids, edges = queue.pop(0)
                if ids[-1] == end["id"]:
                    return {
                        "found": True,
                        "from": start,
                        "to": end,
                        "path": {
                            "nodes": [node(i) for i in ids],
                            "edges": edges,
                            "hops": len(edges),
                        },
                        "observedDataMovement": bool(edges)
                        and all(e.get("observedDataMovement") for e in edges),
                    }
                for e in graph["edges"]:
                    if e["from"] == ids[-1] and e["to"] not in seen:
                        seen.add(e["to"])
                        queue.append((ids + [e["to"]], edges + [e]))
            return {
                "found": False,
                "from": start,
                "to": end,
                "message": "No path in collected relationships; missing telemetry may hide paths.",
            }
        raise APIError("Endpoint not found", 404)

    def iam_api(self, tail, params):
        principals = self.all("principals")
        resources = self.all("resources")
        action = tail[0] if tail else "analysis"
        if action == "principals":
            if len(tail) > 1:
                p = self.find("principals", tail[1])
                if len(tail) > 2 and tail[2] == "activity":
                    events = self.filtered(
                        [
                            e
                            for e in self.all("evidence")
                            if e.get("identity") == p["arn"]
                        ],
                        params,
                    )
                    return {
                        "principal": p,
                        "activity": events,
                        "totalEvents": len(events),
                    }
                return {
                    **p,
                    "accessedResources": [
                        r for r in resources if r["id"] in p["resourcesAccessed"]
                    ],
                    "baseline": self.store.get("baselines", p["id"]),
                }
            rows = principals
            for field in ["canAccessPhi", "hasExcessiveAccess"]:
                if field in params:
                    if str(params[field]).lower() not in ["true", "false"]:
                        raise APIError(field + " must be true or false")
                    rows = [
                        p
                        for p in rows
                        if p.get(field) == (str(params[field]).lower() == "true")
                    ]
            return {"total": len(rows), "principals": rows}
        phi = [p for p in principals if p.get("canAccessPhi")]
        excessive = [p for p in principals if p.get("hasExcessiveAccess")]
        from .analysis import matches

        decrypt = [
            p
            for p in principals
            if any(
                e["effect"] == "Allow" and matches(e["action"], "kms:Decrypt")
                for e in p.get("permissions", [])
            )
        ]
        trusts = [
            {"principal": p, "trust": t}
            for p in principals
            for t in p.get("crossAccountTrust", [])
        ]
        if action == "decrypt-access":
            return {
                "principalsWithDecryptAccess": decrypt,
                "keys": [r for r in resources if r["type"] == "KMS"],
                "note": "Candidate identity permissions; key policy, grants, denies and conditions can change effective access.",
            }
        if action == "cross-account":
            return {"totalCrossAccountTrusts": len(trusts), "trusts": trusts}
        if action == "excessive-access":
            return {
                "total": len(excessive),
                "violations": excessive,
                "note": "Uses configured expected_access; absent expectations do not establish least privilege.",
            }
        if action == "analysis":
            return {
                "summary": {
                    "totalPrincipals": len(principals),
                    "canAccessPhi": len(phi),
                    "hasExcessiveAccess": len(excessive),
                    "externalPrincipals": len(trusts),
                },
                "phiAccessors": phi,
                "excessiveAccessPrincipals": excessive,
                "decryptAccessPrincipals": decrypt,
                "riskyPermissions": [
                    {"principal": p["arn"], **e}
                    for p in principals
                    for e in p.get("permissions", [])
                    if e.get("note")
                ],
                "keyFindings": [],
                "limitations": [
                    "Identity policies are candidate access, not full effective authorization.",
                    "SCPs, resource policies, boundaries, session policies and conditions require review.",
                ],
            }
        raise APIError("Endpoint not found", 404)

    def exposure_api(self, tail, params):
        resources = self.all("resources")
        principals = self.all("principals")
        findings = self.filtered(self.all("findings"), params)
        if not tail:
            return {
                "total": len(findings),
                "findings": findings,
                "summary": counts(findings, "severity"),
            }
        if tail[0] == "public":
            public = [r for r in resources if r.get("publicAccess") is True]
            return {
                "totalPublicResources": len(public),
                "publicPhiResources": sum(sensitive(r) for r in public),
                "exposures": [
                    {
                        "resource": r,
                        "findings": [f for f in findings if f["resourceId"] == r["id"]],
                    }
                    for r in public
                ],
                "unknownPublicStatus": sum(
                    r.get("publicAccess") is None for r in resources
                ),
                "alert": "Review coverage before interpreting absence of exposure findings.",
            }
        paths = [
            {
                "principal": p,
                "trust": t,
                "accessibleResources": [
                    r for r in resources if r["id"] in p.get("candidateResources", [])
                ],
            }
            for p in principals
            for t in p.get("crossAccountTrust", [])
        ]
        if tail[0] == "cross-account":
            return {
                "totalCrossAccountPaths": len(paths),
                "crossAccountExposures": paths,
                "pathsToPhiData": sum(
                    any(sensitive(r) for r in p["accessibleResources"]) for p in paths
                ),
            }
        if tail[0] == "third-party":
            trusted = self.config["trusted_accounts"]
            paths = [
                p
                for p in paths
                if not any(a in str(p["trust"]["principal"]) for a in trusted)
            ]
            for path in paths:
                import re

                accounts = re.findall(
                    r"(?<!\d)\d{12}(?!\d)", str(path["trust"]["principal"])
                )
                owners = [
                    self.config.get("third_parties", {}).get(account)
                    for account in accounts
                    if self.config.get("third_parties", {}).get(account)
                ]
                path["configuredOwners"] = owners
                path["ownershipVerifiedByTool"] = False
                path["recentSensitiveAccess"] = [
                    e
                    for e in self.all("evidence")
                    if e.get("identity") == path["principal"]["arn"]
                    and e.get("successful")
                    and any(
                        touches(e, r["arn"]) and sensitive(r)
                        for r in path["accessibleResources"]
                    )
                ]
                path["operationalNeedConfigured"] = path["principal"][
                    "arn"
                ] in self.config.get("expected_access", {})
            return {
                "thirdPartyAccess": paths,
                "totalVendors": len(
                    {str(owner) for path in paths for owner in path["configuredOwners"]}
                ),
                "unverifiedExternalPaths": sum(
                    not path["configuredOwners"] for path in paths
                ),
                "note": "Ownership labels are operator-supplied; an external trust is not proof of a vendor relationship.",
            }
        raise APIError("Endpoint not found", 404)

    def logs_api(self, method, tail, params):
        groups = [r for r in self.all("resources") if r["type"] == "CloudWatchLogs"]
        findings = self.filtered(
            [f for f in self.all("findings") if f["type"] == "SENSITIVE_DATA_IN_LOGS"],
            params,
        )
        if tail == ["groups"]:
            return {
                "total": len(groups),
                "logGroups": groups,
                "withPhiDetected": len({f["resourceId"] for f in findings}),
                "withoutEncryption": 0,
            }
        if tail == ["findings"]:
            return {"total": len(findings), "findings": findings}
        if len(tail) >= 3 and tail[0] == "groups" and tail[-1] == "findings":
            name = "/".join(tail[1:-1])
            g = next((g for g in groups if g["name"] in [name, "/" + name]), None)
            if not g:
                raise APIError("Log group not found", 404)
            rows = [f for f in findings if f["resourceId"] == g["id"]]
            return {
                "logGroup": g,
                "findings": rows,
                "totalPhiEntries": sum(f.get("matchCount", 0) for f in rows),
            }
        if tail == ["search"] and method == "POST":
            report = self.scan(params, "logs")
            rows = [
                f for f in report["findings"] if f["type"] == "SENSITIVE_DATA_IN_LOGS"
            ]
            return {
                "searchId": report["scanId"],
                "status": report["status"],
                "results": rows,
                "totalMatches": sum(f.get("matchCount", 0) for f in rows),
                "coverage": report["coverage"],
                "logGroupsSearched": [r["name"] for r in report["resources"]],
            }
        raise APIError("Endpoint not found", 404)
