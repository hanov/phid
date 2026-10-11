[![Tests](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/test.yml/badge.svg)](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/test.yml) [![Lint](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/lint.yml/badge.svg)](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/lint.yml) [![Build](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/build.yml)

# phid — Personal Health Information Detector

**Not a developer?** Every healthcare organization stores patient information — names, dates of birth, diagnoses, insurance details — across dozens of cloud systems. Keeping track of where that data lives, who can reach it, and whether it was ever seen by the wrong person is a full-time job no team can do manually. **phid** does it automatically. It connects to your Amazon cloud account, reads the evidence silently (it never changes anything), and produces a clear picture: where patient data exists, which staff or systems can access it, whether anything unusual happened, and whether any information ended up somewhere it should not be. When it finds a concern it writes a plain-language incident report with a recommended next step — no engineering background required to read it. Patient data never leaves your own systems; all analysis runs locally on your machine.

---

**Catch patient data accidents before they become incidents.**

phid continuously watches your AWS infrastructure for signs that protected health information (PHI) or personal data (PII) is exposed, mishandled, or accessed in unexpected ways — and alerts your team before a small oversight becomes a reportable breach. It is read-only: it never modifies your data, never changes permissions, and never sends anything outside your network.

| Cloud | Status |
|---|---|
| AWS | ✅ Current |
| Google Cloud | 🗓 Planned Q1 2027 |
| Azure | 🗓 Planned Q2 2027 |

---

## Quick start

```bash
# Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Run your first scan
export AWS_PROFILE=your-profile
phid scan --no-tui --output scan.json

# Review what was found
phid findings --severity HIGH
phid report --html report.html
```

**macOS Apple Silicon binary** (no Python required):

```bash
curl -fsSL https://phid.amirkhanov.org/install.sh | bash -s -- --base-url https://phid.amirkhanov.org
phid --version
```

---

## What it does

- 🔍 **Discovers** PHI and PII across S3, RDS, DynamoDB, CloudWatch logs, and more
- 🗺 **Maps** data lineage — where sensitive data originates, moves, and is stored
- 👤 **Analyzes** IAM roles and identifies who can access patient data
- 📊 **Detects** unusual access patterns, bulk downloads, and behavioral anomalies
- 🚨 **Investigates** potential incidents with correlated evidence from CloudTrail, VPC Flow Logs, KMS, Macie, and GuardDuty
- 📄 **Reports** findings as plain-language incident reports and self-contained HTML dashboards
- 🔒 **Never** modifies data, changes permissions, or sends PHI outside your systems

---

## Installation

Requires Python 3.9+ and an AWS account with read-only credentials.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
phid --man        # full manual
phid --help       # command list
```

For PostgreSQL / Aurora / Redshift sampling:

```bash
pip install -e '.[databases]'
```

For local NLP classification:

```bash
pip install -e '.[nlp]'
```

The database is created at `data/phi-security.db` by default. Override with `--db FILE` or `PHI_DB`. Use a separate database per AWS account.

---

## Usage

### Scan AWS

```bash
phid scan                                          # full scan, interactive
phid scan --no-tui --output report.json            # non-interactive
phid scan --scope s3                               # S3 only
phid scan --scope logs --from 24h                 # logs from last 24 hours
phid scan --regions us-east-1,us-west-2           # specific regions
phid scan --skip iam,telemetry                     # exclude services
```

### Review results

```bash
phid health                                        # account and DB status
phid inventory --classification PHI_HIGH           # sensitive resources
phid findings --severity HIGH                      # high-severity findings
phid exposure --view public                        # publicly exposed data
phid iam --view principals                         # IAM access analysis
phid logs --view groups                            # log group findings
phid data-map                                      # data lineage graph
```

### Investigate

```bash
phid investigate --resource s3://patient-records  # investigate a resource
phid investigations                                # list investigations
phid incidents                                     # list incidents
phid incident inc-EXAMPLE --view evidence          # inspect an incident
phid incident inc-EXAMPLE --note "Reviewed"        # add a note
phid ask "Who accessed patient data yesterday?"    # natural-language query
phid ask "Was PII written into logs today?"
```

### Monitor continuously

```bash
phid agent --interval 300                          # scan every 5 minutes
phid agent --once --scope s3                       # single cycle
phid cycles                                        # cycle history
```

---

## Command reference

| Command | Description |
|---|---|
| `scan` | Collect AWS evidence across all or scoped services |
| `inventory` | List discovered resources |
| `findings` | List findings; filter by `--severity`, `--classification` |
| `evidence` | List evidence records |
| `data-map` | Show sensitive data lineage; `--dot FILE` for Graphviz |
| `iam` | Analyze IAM roles and excessive access to PHI |
| `exposure` | Show public, cross-account, or third-party exposure |
| `logs` | CloudWatch log group PHI/PII findings |
| `investigate` | Run an investigation against a resource or identity |
| `investigations` | List investigation reviews |
| `incidents` | List detected incidents |
| `incident` | Inspect an incident; `--note TEXT` to annotate |
| `baselines` | Behavioral baselines; `--recalculate --days N` |
| `ask` | Natural-language questions from stored evidence |
| `classify` | Detect PHI/PII in text or a file |
| `controls` | Technical control observations |
| `health` | Local DB and AWS account status |
| `report` | Export findings as HTML or JSON |
| `agent` | Continuous monitoring; `--interval N` seconds |
| `config-check` | Show resolved config (DB path, regions, LLM) |

---

## Local AI

phid works fully without AI. When you have [Ollama](https://ollama.com) running locally, it can use it to reason over stored evidence:

```bash
phid ask "Which IAM roles can decrypt patient data?" --llm ollama --model gemma3:4b
phid classify --input sample.txt --llm ollama --model gemma3:4b
phid investigate --resource medical-bucket --config config/local-example.json
```

Configure models by role in `config/local-example.json`:

```yaml
llm:
  provider: ollama
  models:
    fast: gemma3
    classification: qwen3
    reasoning: qwen3
    report: llama3
```

For in-process inference (no Ollama required):

```bash
pip install -e '.[local-ai]'
phid ask "..." --llm local --model /path/to/model.gguf
```

> **Privacy guarantee:** PHI and PII are redacted before reaching any model. Only metadata and redacted context are used for reasoning. No remote inference providers are supported.

---

## HTML dashboard

Generate a self-contained HTML report — no JavaScript, CDN, or server needed:

```bash
phid scan --html report.html
phid report --html report.html     # regenerate from existing DB
```

Open `report.html` in any browser. Includes severity totals, all findings, resources, incidents, evidence, and coverage.

---

## Configuration

<details>
<summary>Advanced configuration options</summary>

Configuration accepts flat JSON or nested YAML. Select a config file with `--config FILE` or `PHI_CONFIG`. Select the database with `--db FILE` or `PHI_DB`.

**Key options:**

| Option | Description |
|---|---|
| `aws.profile` | AWS profile name |
| `aws.regions` | List of regions to scan |
| `detection.log_phi_detection` | Detect PHI leaked into logs |
| `detection.bulk_access_detection` | Flag unusual bulk data reads |
| `detection.data_exfiltration_detection` | Flag potential data exfiltration |
| `privacy.redact_before_llm` | Redact PHI before sending to local model |
| `llm.provider` | `ollama` or `local` |
| `storage.path` | SQLite database path |
| `agent.interval` | Monitoring cycle interval in seconds |

**Custom PII patterns:**

```yaml
sensitive_data:
  custom_patterns:
    - name: medical_record_number
      regex: "MRN-[0-9]{8}"
    - name: patient_account_id
      regex: "PAT-[A-Z0-9]{12}"
```

**Approved activity (noise reduction):**

```yaml
approved_activity:
  - identity: arn:aws:iam::123456789012:role/patient-api
    resource: s3://patient-records
    reason: "Nightly ETL job"
```

See `config/example.json` and `phid --man` for the full reference.

</details>

---

## Container

```bash
docker build -t phid .
docker run --rm phid --man
docker run --rm \
  -v phi-data:/data \
  -v "$HOME/.aws:/home/phi/.aws:ro" \
  -e AWS_PROFILE=production \
  phid scan
```

The container runs a single CLI command and exits. No ports are exposed.

---

## Limitations

- IAM policy matches represent **candidate** access, not full effective authorization.
- Relationships do not necessarily represent observed data movement.
- Missing telemetry does not establish absence of exposure.
- Findings do not confirm a breach — review coverage and evidence before drawing conclusions.

```bash
python3 -m unittest discover -s tests_python -v
```

See [`docs/implementation.md`](docs/implementation.md) for current coverage details.

---

## License

phid (`phi-security`) is **source-available** under [PolyForm Noncommercial 1.0.0](LICENSE).
Commercial use — including internal security operations, paid assessments, and redistribution — requires a separate license.

Contact [license@amirkhanov.org](mailto:license@amirkhanov.org) · See [COMMERCIAL.md](COMMERCIAL.md) for details.
`phid` is the primary command; `phi-sec` remains a compatibility alias.
