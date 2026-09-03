# Python CLI implementation

The application has no server, REST endpoints, JavaScript, or Node runtime. CLI commands call Python functions and local SQLite directly. boto3 is used only for allowlisted AWS reads. Optional inference talks to an **already-running loopback Ollama**, or loads a local GGUF model in process. Hosted model providers have been removed. The method/path strings retained in `Engine.dispatch` are private in-process query identifiers, not network endpoints.

## Implemented workflows

| Area | Implementation |
|---|---|
| CLI, config, storage | argparse entry points, manual, JSON/YAML config, validated bounds, AWS profile/region selection, account-isolated SQLite, private report files, locks and retention. |
| Local AI | `llm.Router`: model roles, loopback-only Ollama with proxies/redirects disabled, optional in-process GGUF, minimized/redacted context, structured output, validated evidence references, persistent model-run metadata. |
| Questions | Evidence-backed intents for inventory, candidate access/decryption, observed access, log leakage and movement. Known resources and UTC today/yesterday selection; search fallback; optional advisory reasoning. |
| Classification | Regex, JSON schema fields, high-entropy token detection, custom category mappings, optional installed local NLP, strongest-classification preservation, standalone classify command. |
| Inventory | S3, database families, compute/workloads, IAM, keys, snapshots, backups and application/network configuration. Bounded object metadata/prefix inventory is opt-in. |
| Sampling | Explicit bounded S3 keys and log objects; explicit DynamoDB tables (1–10 evaluated items); optional PostgreSQL/Aurora PostgreSQL and Redshift read-only transactions with row/column/cell/time bounds. No raw sample persistence. |
| Telemetry | CloudTrail management and configured data-event log ingestion, canonical event IDs and legacy deduplication, flow logs, CloudWatch logs, explicit ALB/S3 log objects, expanded workload metrics, optional Config history and Organizations account metadata. |
| Security integrations | Macie classification; GuardDuty resource/identity context; Security Hub/Access Analyzer findings joined to sensitive assets; Config relationships and change hashes. |
| IAM/KMS | Service-aware candidate reads with unconditional deny checks; write/export/query/decrypt capability lists; configured least privilege; MFA registration context; new permission and decrypt-grant observations; key-sharing scope. |
| Behavioral analysis | Historical dimensions, corroborated novelty, off-hours, approved activity/CIDR suppression, cross-account access, decrypt and metric volume, network novelty with optional supplied ASN/country/VPC context. |
| Correlation | Time-bounded unique reads + decrypt + linked external network activity; egress alone never establishes exfiltration. Presigned authentication is a review observation, not proof of public sharing. |
| Investigation | Bounded identity/session, resource, network and disconfirming-evidence queries. Optional local planner can order fixed query templates only. Expected activity, denied requests and approved IPs are recorded with caveats. |
| Agent | Foreground scan cycles, bounded high-severity triage, evidence-fingerprint deduplication, persisted cycle/investigation records, no repeated content sampling by default. |
| Finding lifecycle | Complete scoped collection may resolve absent configuration findings. Partial scans and historical behavior never resolve findings merely through absence. |
| Lineage | Execution roles, logs, configured API integrations/load-balancer targets/routes, backup inheritance, KMS encryption, replication and observed copies. JSON graph, DOT export and HTML relationships. |
| Privacy controls | Sensitive log/payload findings, component and candidate-reader context, retention/backup age, exposure/encryption/access findings, technical control observations with explicit unknown states. |
| Reports | JSON and private, atomic, self-contained HTML: all retained findings, resources, incidents, evidence, investigations, relationships and controls. Local model commentary is separately labeled advisory. |

## Safety and interpretation

- Model text never creates evidence or executes commands. Validating an evidence ID does **not** prove that the model's prose is correct; commentary remains unverified.
- `minimum_incident_confidence` is a threshold on a documented source-diversity heuristic, not a statistical breach probability. Default 0 retains observed findings for human review.
- Identifiers needed for joins are retained. Known raw payload and credential fields are removed at storage; log/sample content is represented by hashes/types. Arbitrary sensitive information embedded in resource identifiers cannot be universally recognized.
- All operations remain bounded by configured coverage limits. Collection gaps and unavailable metrics are reported explicitly.
- Candidate permissions and configured routes do not establish effective authorization or actual reachability. Conditions, SCPs, session policies, boundaries, grants and resource-policy interactions require review.
- Findings do not establish legal compliance/non-compliance or a breach. Exact patient counts, destination ownership, business authorization and root cause cannot be inferred from API counts alone.

## Remaining limits against the broader vision

The implementation covers the principal workflows, but it is **not a claim that every example in todo.txt is fully automated**:

- Direct record sampling currently supports DynamoDB and PostgreSQL-compatible stores. MySQL/Aurora MySQL, DocumentDB and OpenSearch record sampling are not implemented; those services use metadata and routed logs.
- Investigation expansion is bounded over collected evidence after an optional AWS refresh. It is not an unrestricted adaptive AWS query agent; model planning is limited to the four reviewed query templates.
- Configured topology is incomplete where integrations are not exposed in collected metadata (application SQL calls, EKS pod roles, custom ETL paths and some cross-account boundaries).
- NLP is optional and requires a locally installed model. Semantic medical/image interpretation is not a built-in diagnostic classifier.
- Technical-control observations are not comprehensive formal HIPAA/SOC2/NIST/CIS/GDPR/ISO assessments. Unknown workload controls remain unknown.
- Scanning is sequential; large accounts require configured scope/budgets and coverage review. Conditional whole-account `PARTIAL` results intentionally prevent automatic global finding resolution.
- No live AWS or direct database validation was performed in this implementation session. Optional GGUF/NLP/database dependencies were not installed or exercised against real services.

## Validation

Run:

```sh
python3 -m unittest discover -s tests_python -v
```

The suite covers the original engine, CLI/HTML, requirement acceptance, local inference protocol validation, read-only allowlists, scoped lifecycle, canonical event counts, classification precedence, approved activity, bounded sampling, graph escaping and botocore parameter shapes. Python tests are defined against user-visible behavior; removed HTTP transport tests are not requirements.

A real local Ollama smoke test passed with `qwen2.5:3b` and a synthetic event, validating its returned evidence ID. Reproduce with:

```sh
PYTHONPATH=. python3 examples/local_inference_smoke.py
```

Local inference protocol references: [Ollama chat documentation](https://github.com/ollama/ollama/blob/main/docs/api.md), [llama-cpp-python structured chat](https://llama-cpp-python.readthedocs.io/en/latest/).
