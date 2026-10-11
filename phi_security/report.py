"""Self-contained, script-free HTML dashboards from stored scan evidence."""

import json
import os
import tempfile
from collections import Counter
from html import escape
from pathlib import Path

from .analysis import RANK
from .storage import now


def snapshot(engine):
    return {
        "generatedAt": now(),
        "account": engine.store.meta("account"),
        "lastScan": engine.store.meta("lastScan"),
        **{
            kind: engine.all(kind)
            for kind in [
                "findings",
                "resources",
                "incidents",
                "evidence",
                "investigations",
            ]
        },
        "graph": engine.graph(),
        "controls": __import__("phi_security.controls", fromlist=["assess"]).assess(
            engine.all("resources"), engine.all("findings"), engine.all("evidence")
        ),
    }


def text(value):
    return escape(str(value if value is not None else "Unknown"), quote=True)


def details(value):
    return (
        "<details><summary>Full details</summary><pre>"
        + text(json.dumps(value, indent=2, default=str))
        + "</pre></details>"
    )


def table(headers, rows):
    body = "".join(
        "<tr>" + "".join("<td>" + cell + "</td>" for cell in row) + "</tr>"
        for row in rows
    )
    if not body:
        body = (
            '<tr><td colspan="'
            + str(len(headers))
            + '">No records available.</td></tr>'
        )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join('<th scope="col">' + text(h) + "</th>" for h in headers)
        + "</tr></thead><tbody>"
        + body
        + "</tbody></table></div>"
    )


def render_dashboard(data, operation=None):
    findings = sorted(
        data["findings"],
        key=lambda f: (RANK.get(f.get("severity"), 99), str(f.get("id", ""))),
    )
    resources = {r["id"]: r for r in data["resources"]}
    last = data.get("lastScan") or {}
    counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
    cards = "".join(
        '<div class="card"><strong>'
        + str(len(data[k]))
        + "</strong><span>"
        + label
        + "</span></div>"
        for k, label in [
            ("findings", "Findings"),
            ("resources", "Resources"),
            ("incidents", "Incidents"),
            ("evidence", "Evidence records"),
        ]
    )
    bars = (
        "".join(
            '<div class="bar"><span>'
            + text(severity)
            + '</span><meter min="0" max="'
            + str(max(len(findings), 1))
            + '" value="'
            + str(counts[severity])
            + '">'
            + str(counts[severity])
            + "</meter><b>"
            + str(counts[severity])
            + "</b></div>"
            for severity in sorted(counts, key=lambda s: RANK.get(s, 99))
        )
        or "<p>No findings stored.</p>"
    )
    finding_rows = []
    for finding in findings:
        resource = resources.get(finding.get("resourceId"), {})
        severity = finding.get("severity", "UNKNOWN")
        level = (
            severity.lower()
            if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            else "unknown"
        )
        finding_rows.append(
            [
                '<span class="badge ' + level + '">' + text(severity) + "</span>",
                text(finding.get("title") or finding.get("type") or finding.get("id"))
                + "<br><small>"
                + text(finding.get("id"))
                + "</small>"
                + details(finding),
                text(
                    resource.get("name")
                    or resource.get("arn")
                    or finding.get("resourceId")
                ),
                text(finding.get("classification")),
                text(finding.get("status")),
            ]
        )
    sections = (
        '<section id="findings"><h2>All findings ('
        + str(len(findings))
        + ")</h2>"
        + table(
            ["Severity", "Finding", "Resource", "Classification", "Status"],
            finding_rows,
        )
        + "</section>"
    )
    for kind, columns in [
        ("resources", ["name", "type", "region", "classification", "riskLevel"]),
        ("incidents", ["id", "title", "severity", "status"]),
        ("evidence", ["id", "source", "eventType", "timestamp"]),
    ]:
        sections += (
            '<section id="'
            + kind
            + '"><h2>'
            + kind.title()
            + "</h2>"
            + table(
                [*columns, "Details"],
                [
                    [*(text(row.get(c)) for c in columns), details(row)]
                    for row in data[kind]
                ],
            )
            + "</section>"
        )
    graph = data.get("graph", {})
    sections += (
        '<section id="relationships"><h2>Data relationships</h2><p>Configuration and candidate paths are not proof of observed data movement.</p>'
        + table(
            ["From", "Relationship", "To", "Observed movement"],
            [
                [
                    text(e.get("from")),
                    text(e.get("relation")),
                    text(e.get("to")),
                    text(e.get("observedDataMovement", False)),
                ]
                for e in graph.get("edges", [])
            ],
        )
        + "</section>"
    )
    sections += (
        '<section id="investigations"><h2>Investigations</h2>'
        + table(
            ["ID", "Disposition", "Details"],
            [
                [text(i["id"]), text(i.get("disposition")), details(i)]
                for i in data.get("investigations", [])
            ],
        )
        + "</section>"
    )
    sections += (
        '<section id="controls"><h2>Technical control observations</h2><p>No legal compliance determination.</p>'
        + table(
            ["Resource", "Control", "Status", "Details"],
            [
                [
                    text(c.get("resourceId")),
                    text(c.get("control")),
                    text(c.get("status")),
                    details(c),
                ]
                for c in data.get("controls", {}).get("checks", [])
            ],
        )
        + "</section>"
    )
    coverage = last.get("coverage") or []
    coverage_html = table(
        ["Service", "Region", "Status", "Details"],
        [
            [
                text(c.get("service")),
                text(c.get("region")),
                text(c.get("status")),
                details(c),
            ]
            for c in coverage
        ],
    )
    if data.get("modelCommentary"):
        sections += (
            "<section><h2>Local model commentary (advisory)</h2>"
            + details(data["modelCommentary"])
            + "</section>"
        )
    current = (
        "<section><h2>Command result</h2>" + details(operation) + "</section>"
        if operation
        else ""
    )
    return (
        """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>PHI/PII Security Scan Report</title><style>
:root{color-scheme:dark;--bg:#0d1117;--surface:#161b22;--border:#30363d;--muted:#aab5c1;--text:#e6edf3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:32px 20px}h1{font-size:30px;margin:0}h2{font-size:21px}a{color:#79c0ff}nav{display:flex;flex-wrap:wrap;gap:20px;margin:20px 0}.meta,small{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}.card,section{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px}.card strong{display:block;font-size:32px}.card span{color:var(--muted)}.bar{display:flex;gap:14px;align-items:center;margin:8px 0}.bar span{width:95px}meter{width:min(65%,600px);height:20px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;text-align:left}th,td{padding:12px;border-bottom:1px solid var(--border);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted)}summary{cursor:pointer;color:#79c0ff}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 monospace;max-width:850px}.badge{border-radius:20px;padding:3px 9px;font-weight:700;font-size:12px;background:#30363d}.critical,.high{color:#ffa198}.medium{color:#e3b341}.low{color:#7ee787}.info{color:#79c0ff}.notice{border-left:4px solid #e3b341;padding-left:16px}@media print{:root{color-scheme:light;--bg:white;--surface:white;--text:black;--muted:#444;--border:#aaa}main{padding:0}.table-wrap{overflow:visible}a,summary{color:black}}
</style></head><body><main><header><h1>PHI/PII Security Scan Report</h1>
<p class="meta">Account: """
        + text(data.get("account"))
        + " · Generated: "
        + text(data["generatedAt"])
        + """</p>
<p>Last scan: """
        + text(last.get("scanId", "No scan recorded"))
        + " · Status: "
        + text(last.get("status", "NOT SCANNED"))
        + " · Completed: "
        + text(last.get("completedAt"))
        + """</p>
<p class="notice">Includes all stored findings, across scan scopes and retained history, without pagination or query filters. Coverage below describes the latest scan only. Missing evidence does not establish absence of exposure; findings do not confirm a breach.</p></header>
<nav aria-label="Report sections"><a href="#findings">Findings</a><a href="#resources">Resources</a><a href="#incidents">Incidents</a><a href="#evidence">Evidence</a><a href="#coverage">Coverage</a><a href="#relationships">Relationships</a><a href="#investigations">Investigations</a><a href="#controls">Controls</a></nav>
<div class="cards">"""
        + cards
        + "</div><section><h2>Findings by severity</h2>"
        + bars
        + "</section>"
        + sections
        + '<section id="coverage"><h2>Latest scan coverage</h2>'
        + coverage_html
        + "</section>"
        + current
        + "<footer>Generated locally by phi-sec. Expand Full details for complete records. Use browser Find to locate text in the dashboard.</footer></main></body></html>\n"
    )


def write_dashboard(path, data, operation=None):
    """Atomically replace a report with an owner-readable/writable UTF-8 file."""
    destination = Path(path)
    content = render_dashboard(data, operation)
    fd, temporary = tempfile.mkstemp(
        prefix=".phi-report-", suffix=".html", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
