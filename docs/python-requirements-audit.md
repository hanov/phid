> Historical audit, before the implementation update. See [implementation.md](implementation.md) for current behavior.

# Python implementation audit against todo.txt

Audit date: 2026-09-29.

**Conclusion: the Python implementation does not implement all of todo.txt.** It provides a working CLI, storage, bounded AWS collection, deterministic classification, basic analysis, and HTML reporting. It is not yet the full AI-powered investigation platform described by the specification. At that audit date, Phase 1 lacked an LLM abstraction; this has since been implemented locally.

This audit covers the current source, configuration, and all three Python test files. All 60 existing tests passed during the audit. No live AWS collection or model inference was performed. Passing tests establish only the cases exercised, not feature completeness or production readiness. This audit predates the subsequent Python implementation work. Tests are now defined against requirements, not removed HTTP transport behavior.

The later user requirements (Python-only, CLI-only, no application API server, HTML dashboard, manual) take precedence over older interface expectations. Those changes do not by themselves implement or replace natural-language reasoning. The previous rewrite also removed the Ollama client; keyword search is a functional reduction, not an equivalent migration. The user subsequently clarified that existing local Ollama is permitted. Remote inference was removed; no application server is permitted.

Status meanings: **Implemented** means the stated bounded capability exists; **Partial** means substantive requirements remain; **Missing** means no working implementation was found; **Alternative** means an architectural recommendation was implemented differently. Collector presence and an AWS allowlist entry are not proof of analysis support.

## Requirement-by-requirement inventory

References below are functions in `phi_security/` unless otherwise indicated.

| todo.txt section | Status | Python evidence and remaining scope |
|---|---|---|
| Opening requirements: CLI and agent, read-only AWS | Partial | `cli.main`, `aws.AWS.call`: working CLI and periodic foreground scans; no adaptive autonomous investigator. Explicit SDK allowlist, no AWS remediation or secret retrieval. |
| Primary mission: PHI/PII and configurable categories | Partial | `privacy.PATTERNS`, `classify`, `metadata_classification`: common regex types, tag/override taxonomy. No broad semantic recognition of treatments, imaging, appointments, biometric/device/employee identifiers. Custom detector labels do not generally map to custom classification categories. |
| Important design principle | Partial | Sensitive-resource analysis, candidate access, observed reads, and correlation exist. Complete data origin, expected use, movement, and authorization reasoning does not. |
| Investigation model | Partial | `Engine.scan`, `investigate`, `analysis.analyze`, `correlation.correlate`: basic pipeline, but no iterative planning and no complete outcome taxonomy. |
| LLM backends: Ollama and role-specific models | Missing | No Python Ollama client, shared router, or fast/classification/reasoning/report model selection. `ask` is keyword search. |
| AWS Bedrock | Partial | `bedrock.query` has opt-in Converse inference and JSON parsing; internal dispatcher can call it. No CLI/provider abstraction integration or per-role model configuration. |
| PHI/PII privacy boundary | Partial | `privacy.detect/safe`, content fingerprints, metadata-only log evidence. Remote input pattern checking exists, but there is no complete configurable redaction/tokenization pipeline. |
| Sensitive-data discovery: S3 | Partial | `Collector.s3`: bucket tags, policies, ACL/block configuration, default encryption, logging/versioning settings, replication, explicit bounded content samples. No general object metadata/prefix inventory or S3 access-log ingestion. Allowlisted list/head operations are not actually used for discovery. |
| Databases | Partial | `Collector.databases` inventories all six requested service families. Glue schema hints enrich matching S3 resources; DynamoDB inspects key definitions only. No direct schema inspection or limited database-record sampling. |
| CloudWatch and application logs | Partial | `Collector.logs`: bounded CloudWatch scanning, including application logs routed there. No direct ALB/S3/OpenSearch log ingestion, entropy detector, NLP, or safe LLM classification. |
| Sensitive-data detectors | Partial | Many requested regex types and custom regexes exist. No semantic detector pipeline or comprehensive accuracy tests; some requested identifiers need custom patterns. |
| Data classification | Partial | Built-in labels, overrides, tags, custom taxonomy sensitivity flags. Custom examples do not train/drive classifiers; no custom detector-to-taxonomy mapping. |
| Sensitive-data inventory | Implemented | `Store`, `Engine.summary/dispatch`: persisted resources, classifications, encryption, candidate/observed access and evidence. Accuracy remains limited by collection and classification. |
| Data lineage | Partial | `Collector.edge`, `Engine.graph/graph_api`: candidate access, replication, observed copies, selected configuration edges and path search. No complete end-to-end origin/processor/recipient or network-boundary lineage. |
| Infrastructure graph | Partial | Lambda/ECS execution and logging, EKS roles, KMS grants, CloudFront origins and Config relationships. No complete API Gateway-to-Lambda-to-database topology or resolved network routing. |
| IAM analysis | Partial | `analysis.permissions`, `Engine.iam_api`: read/decrypt candidate permissions, wildcards, trust. No complete write/export analysis, recently gained permissions, or effective authorization evaluation. |
| Least privilege | Implemented | `permissions` compares candidate access with configured `expected_access`; it cannot infer business need when expectations are absent. |
| Access behavior | Partial | `baseline`: daily read-count history. No per-asset/classification/action/region transitions or short-window behavioral profiles. |
| CloudTrail | Partial | `telemetry/cloudtrail_event`: management lookup and configured CloudWatch data-event ingestion, identity/session/source metadata. No complete policy/session/change sequence analysis; data events must already be available. |
| S3 data access | Partial | Successful reads and some session/bytes metadata collected. No new-prefix/region/principal/off-hours detectors; potential event double counting documented below. |
| Network monitoring | Partial | `flow_event` parses default 14-field records; `correlate` checks external egress linked by IP/interface and time. No first-seen, ASN/country, unusual-port, east-west, or cross-VPC anomaly models. |
| Data exfiltration investigation | Partial | Bulk reads + nearby decrypt + linked external flow produces `possible_exfiltration`; egress alone does not. No expected-workload model, decrypt-volume baseline, or destination novelty model. |
| CloudWatch Metrics | Partial | `telemetry` collects EC2 NetworkOut only. No listed S3/Lambda/RDS/DynamoDB/OpenSearch/ALB/API Gateway metrics or metric anomaly analysis. |
| Sensitive-data leakage in logs | Partial | `analyze` produces log findings with counts, types, timestamps and incidents. No root-cause analysis, unique affected-record estimation or full component attribution in the finding. |
| API payload leakage | Partial | Generic regexes detect recognizable sensitive values inside logs. No request/response-body-specific finding or debug/exception/reverse-proxy source diagnosis. |
| Data exposure | Partial | Public S3/RDS/snapshots, attached open groups, external policies/trust are handled. No complete public API, presigned URL, public OpenSearch policy/reachability analysis. |
| Encryption analysis | Partial | Store encryption metadata, KMS policies/grants and candidate decrypt access. No key overuse, new decrypt principal, or anomalous decrypt-volume analysis. |
| Backups and snapshots | Partial | EBS/RDS/Redshift snapshots, AMIs, vaults/recovery points inventoried. No age/retention finding, complete source sensitivity inheritance, dump/export discovery, or destination validation. |
| Non-production environments | Partial | Name/tag heuristic raises `SENSITIVE_NON_PRODUCTION`; does not prove production-data provenance or detect actual copy chains into developer accounts. |
| Cross-account PHI movement | Partial | Trust, external policies, grants, snapshot shares and configured destination accounts. No Organizations-based ownership analysis (operation only allowlisted), complete movement tracking, or business purpose. |
| Third-party access | Partial | `exposure_api` filters external trust using trusted accounts. Vendor ownership, operational need, and recent sensitive-data access are not resolved. |
| Amazon Macie | Partial | Findings enrich matching bucket classification and evidence. Financial/credential distinctions are reduced to PHI/PII; no deep dedicated contextual investigation. |
| GuardDuty | Partial | Findings are collected with resource metadata. No normalization into affected identity/resource links or subsequent sensitive-access investigation in `analyze`. |
| Security Hub | Partial | Active resource findings join sensitive assets and create generic control findings. No control-specific interpretation or detailed privacy prioritization. |
| Access Analyzer | Partial | Active findings join sensitive resources. No deeper conditions/effective-access or actual cross-account access investigation. |
| AWS Config | Partial | Current relationships collected. `get_resource_config_history` is allowlisted but not called; no configuration-change chronology. |
| Privacy incidents | Partial | Persisted incidents, linked evidence/timeline, notes and recommendations. Confidence and affected-record estimates are null; no complete expected/observed behavior or impact report. |
| Privacy findings vs incidents | Implemented | Configuration-only findings do not create incidents; observed log leaks, anomalous reads and bulk correlations can create review incidents. Human review remains explicit. |
| Investigation loop | Partial | Single refresh, evidence selection and fixed hypotheses. No targeted iterative queries or adaptive convergence. |
| Hypothesis reasoning | Partial | `_hypotheses`: bulk, unexpected IP, cross-account and fallback hypotheses. Mostly static missing-evidence prompts; no active search for disconfirming evidence or confidence assessment. |
| Evidence model | Implemented | Stable IDs, source, event, resource, identity, time and referenced records; conclusions generally link evidence. |
| Evidence references | Partial | Event-derived references, ARNs, groups, sessions, metrics and finding IDs exist. Object prefixes and query provenance are not consistently preserved as explicit fields. |
| PHI-safe evidence storage | Partial | Log and sample content stored as hashes/types rather than raw payloads. No universal sanitization boundary in `Store.put`; metadata/policy/resource strings are not all redacted. |
| Prompt injection protection | Partial | Deterministic CLI never executes log instructions. Bedrock system prompt treats context as untrusted; no adversarial tests or enforced planner/tool boundary because planner is absent. |
| External LLM protection | Partial | Remote provider defaults disabled and rejects recognized sensitive patterns. No full per-field policy/tokenization/context minimization or explicit raw-PHI/PII policy configuration. |
| LLM trust boundary | Missing | No model-driven query/reasoning workflow or evidence validation for generated claims. Bedrock JSON output is not checked against stored evidence IDs. |
| AWS API safety | Implemented | Concrete `ALLOW`, bounded explicit S3 keys/range, SDK errors sanitized; mutation and secret-read rejection tested. Bedrock inference is a separate opt-in SDK path. |
| CLI | Partial | All named command names exist, but `ask` is not natural-language investigation; `logs` queries stored findings (use `scan --scope logs` to collect). Manual and HTML report are later additions. |
| Targeted scanning | Partial | Scope, resource, classification, identity and time parameters exist. S3 URI post-filter defect below; other services are largely collected then filtered, not truly targeted. |
| Autonomous mode | Partial | Serial foreground scans, graceful loop stop, lock, cycle persistence. No lightweight triage/adaptive investigation; explicitly enabled sample keys are read on every relevant cycle. |
| Baselines | Partial | Daily totals with insufficient-history handling; no action/resource/classification-specific baselines from the examples. |
| Privacy-aware anomaly scoring | Partial | `compute_risk_score`: sensitivity, public exposure, encryption and candidate-principal baseline deviation. No full identity/IP/region/time/cross-account/Internet/decrypt factors; `events` argument is unused. |
| Compliance context | Partial | Avoids legal-breach assertions; no framework/control mapping. No claim of legal compliance should be inferred. |
| HIPAA-oriented controls | Partial | Encryption, access, logs and least privilege subsets. No dedicated authentication, integrity, transmission, audit-retention and incident-visibility control suite. |
| Architecture | Partial | Python modules for collection, privacy, analysis, storage, CLI/reporting exist. Planner and LLM router absent. |
| Recommended technology | Alternative | Python >=3.9, argparse, boto3, sqlite3 and stdlib rather than recommended Python 3.12+/Typer/Pydantic/Rich/asyncio/httpx. These are recommendations, not missing security capabilities by themselves. |
| Repository | Alternative | `phi_security/` package, `tests_python/`, config/docs/examples/docker directories rather than proposed `src/` tree. Examples directory has no runnable examples. |
| Database | Partial | Generic SQLite entities cover resources, principals, edges, evidence, findings, incidents, baselines, investigations, scans and cycles. No LLM runs, dedicated model migrations, or complete data-asset lifecycle. |
| Example configuration | Partial | Flat JSON plus environment and CLI options; not the nested YAML schema. No model roles, per-detector toggles, remote raw-data policy or agent minimum confidence. |
| Example report | Partial | JSON and offline HTML include all stored findings/details. No reliable semantic cause, affected records, log-reader counts, quantified confidence or comprehensive impact narrative. |
| Data map output | Partial | JSON relationship graph; no rendered classified lineage diagram in CLI/HTML. |
| Security priorities | Partial | Public sensitive data, log leakage, bulk access, unencrypted resources and other basic findings. Missing detectors above prevent all 15 priorities from being covered. |
| Noise reduction | Partial | Approved CIDRs, explicit access expectations, missing-history handling, corroborated flow correlation. No migration schedules, expected sessions, broader context suppression or calibrated false-positive evaluation. |
| Investigation depth | Missing | No loop to reach the requested benign/expected/probable unauthorized/probable exposure outcomes. Current conclusion is confirmed access or insufficient evidence with human review. |
| Important distinction | Partial | Configuration risk, privacy finding, security anomaly, confirmed access and possible exfiltration labels exist. No complete distinct suspected-exposure/authorization assessment model. |
| Final goal and phased implementation | Partial | Useful deterministic foundation, not the completed AI investigator. See phase assessment below. |

## Confirmed defects and implementation risks

These are separate from unimplemented features. Production code was not changed during this audit.

1. **S3 URI targeting can return an empty report for a collected bucket.** `Collector.s3` accepts `s3://medical`, but `Engine.scan` later tests that literal against the ARN/name/ID. A fixture scan with `resource='s3://medical'` returned zero selected resources. The exact example syntax in todo.txt therefore does not work end to end.
2. **One CloudTrail GetObject can count twice.** `cloudtrail_event` emits one row for the object ARN and another for the bucket from requestParameters. A synthetic single-event check yielded two rows, both matching the bucket correlation. Baseline and bulk logic count rows, potentially inflating read counts. Preserve a canonical source event ID and count unique events when aggregating.
3. **Classification can decrease with collection order.** In `Collector.logs`, each detected event overwrites the group's classification; a later email can replace an earlier PHI_HIGH classification. S3 samples and later enrichment can likewise overwrite stronger evidence. Classification needs explicit precedence and multi-category treatment.
4. **Resolved findings remain stored as open.** `Engine.scan` upserts current findings but does not reconcile old findings absent from a new analysis. `report --html` intentionally exports all stored records, so it may show historical open findings after conditions change. Resolution must account for scope and coverage rather than closing findings on incomplete scans.
5. **Custom taxonomy handling is inconsistent.** `sensitive()` honors the resource flag, but `compute_risk_score` uses fixed labels and custom regex names generally classify as PII. A custom high-sensitivity category is not treated consistently through the pipeline.
6. **Read-access matching is not service-aware.** `permissions` independently matches any read action and the resource ARN. A statement allowing an unrelated service read on Resource `*` can produce candidate access to assets of another service. The candidate-access caveat does not resolve this incorrect action/resource association.
7. **Metadata privacy is not comprehensively enforced.** The storage layer accepts arbitrary dictionaries. Content paths use hashes/redaction, but tags/policies/references and other metadata need a field-level review and tests rather than a blanket claim that the database contains no sensitive values.

Items 1 and 2 were reproduced during this audit using synthetic fixtures and temporary storage; items 3–7 are source-review findings and need targeted regression tests.

## Phase assessment

| Phase | Assessment |
|---|---|
| 1: CLI, config, auth, LLM abstraction, SQLite | Partial: LLM abstraction and CLI integration missing. |
| 2: AWS and sensitive inventory | Partial: broad bounded metadata inventory; schema/content/coverage gaps. |
| 3: S3, IAM, KMS, Macie | Partial: collection and basic analysis; defects and missing interpretation. |
| 4: CloudTrail/access behavior | Partial: ingestion and count baselines; deduplication and behavioral gaps. |
| 5: CloudWatch detection | Partial: deterministic patterns; classifier/order and attribution gaps. |
| 6: Lineage | Partial: relationship graph, not complete data lineage. |
| 7: Investigation engine | Partial: fixed review, no iterative investigator. |
| 8: Anomaly/baseline engine | Partial: daily count deviations, not multidimensional baselines. |
| 9: GuardDuty/Security Hub/Config/Access Analyzer | Partial: collection exists, interpretation uneven. |
| 10: Autonomous monitoring | Partial: periodic scan loop, not adaptive triage/investigation. |

## Tests and next implementation order

Current suite: 42 engine/security/analysis tests, 11 CLI tests, 7 HTML-report tests. Many endpoint-style engine tests only assert dictionary responses. At the audit date there was no exhaustive AWS service-fixture suite. In particular, provider success/error paths, most collectors/integrations, lifecycle reconciliation, detector accuracy and complete investigation workflows need coverage.

Suggested order:

1. Fix and regression-test targeting, event deduplication, classification precedence, service-aware IAM matching, and scoped finding lifecycle.
2. Build a requirement-to-test map for Python capabilities; removed HTTP/server behavior is out of scope.
3. Implement a Python provider abstraction and evidence-grounded natural-language workflow, with an explicit decision about the no-server/Ollama constraint; validate remote privacy boundaries and generated evidence references.
4. Implement adaptive investigation and agent triage, richer baselines, and telemetry-specific correlation.
5. Complete discovery, integration interpretation, lineage, controls and reporting gaps in the inventory above.

A full completion claim requires requirement acceptance tests and representative AWS validation, not just an increasing unit-test count.
