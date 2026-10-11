![Tests](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/test.yml/badge.svg)
![Lint](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/lint.yml/badge.svg)
![Build](https://github.com/YOUR_ORG/phi-pii-tool/actions/workflows/build.yml/badge.svg)

> **In plain terms:** Every healthcare organization stores patient information — names, dates of birth, diagnoses, insurance details — across dozens of cloud systems. Keeping track of where that information lives, who can access it, and whether it has ever been seen by the wrong person is a full-time job that no team can do manually. **phid** does that job automatically. It connects to your Amazon cloud account, silently reads the evidence (it never changes anything), and produces a clear picture: where patient data exists, which staff or systems can reach it, whether anything unusual happened, and whether any information may have ended up somewhere it should not be. When it finds a concern it writes a plain-language incident report with a recommended next step for your team — no engineering background required to read it. Patient data never leaves your own systems; all analysis runs locally on your own machine.

# phid — PHI/PII security CLI

Python-only, read-only AWS discovery and investigation. Commands run directly against the Python engine and local SQLite database. No application server or web API layer is created. All operations run through Python CLI commands. Optional AI uses your existing local Ollama or in-process GGUF inference; hosted providers are rejected.

**Cloud platform coverage:** AWS — current. Google Cloud — planned Q1 2027. Azure — planned Q2 2027.

## Quick start

```sh
# Option 1 — Python source (all platforms)
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
phid --version

# Option 2 — pre-built macOS Apple Silicon binary
curl -fsSL https://phid.amirkhanov.org/install.sh | bash -s -- --base-url https://phid.amirkhanov.org

# First scan (needs AWS credentials in the environment)
export AWS_PROFILE=myprofile
phid scan --no-tui --output scan.json   # non-interactive
phid findings --severity HIGH           # review findings
phid report --html report.html          # generate dashboard
```

## Standalone macOS binary

The native Apple Silicon executable is named `phid` and installs at
`/opt/homebrew/bin/phid`. No Python installation is needed to run that binary.

```sh
phid --version
phid --man
phid --license
phid scan --html scan-report.html
```

The binary includes AWS/YAML support and PostgreSQL-compatible database adapters.
It connects to an existing local Ollama when configured. Optional spaCy and
in-process GGUF inference are available through the Python installation below,
not bundled in this binary. AWS credentials and models are not bundled.

Database behavior is unchanged: `data/phi-security.db` relative to your working
directory, or an explicit `--db FILE` / `PHI_DB`. To inspect this repository's
existing evidence from another directory, use its absolute database path.

Rebuild on the target platform in an isolated Python environment:

```sh
python3 -m pip install '.[databases]' 'pyinstaller>=6,<7'
python3 packaging/build_binary.py
```

The output is `dist/phid`. The local macOS build is ad-hoc signed, not Apple-notarized.
`phid` is the primary command; `phi-sec` remains a compatibility alias.

## Install and run

Requires Python 3.9+ and boto3. From this directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
phid --man
phid --help
```

You can also run `python3 -m phi_security` or `python3 -m phi_security.cli` with the same arguments. `phid man` and `phid --man` print the complete manual without opening a database or contacting AWS.

## Scan AWS

Use the standard boto3 credential chain, such as an AWS profile with read-only permissions. See `config/read-only-policy.json` for the collection policy and `config/example.json` for configuration. Environment files are not loaded automatically.

```sh
export AWS_PROFILE=production
phid scan --regions us-east-1,us-west-2 --output report.json
phid scan --scope s3
phid scan --scope logs --from 24h
phid scan --config config/example.json --db data/production.db
```

The default database is `data/phi-security.db`. Existing databases remain usable. Use a separate database per AWS account. Object-content sampling is disabled by default; explicitly configured sampling remains bounded and read-only. Raw log messages are not persisted.

## Review stored results

```sh
phid health
phid inventory --classification PHI_HIGH --limit 100
phid inventory --summary
phid findings --severity HIGH
phid evidence --from 24h
phid data-map
phid iam --view principals
phid exposure --view public
phid logs --view groups
phid classifications
phid ask 'public sensitive data'
```

`ask` routes access, location, log-leakage and movement questions to stored evidence, with keyword search as a fallback. “Today” and “yesterday” use UTC. It can add advisory local-model commentary when configured. Stored-data commands do not call AWS.

```sh
phid investigate --resource medical-bucket --no-refresh
phid investigations
phid investigations inv-EXAMPLE --view timeline
phid incidents
phid incident inc-EXAMPLE --view evidence
phid incident inc-EXAMPLE --note 'Reviewed by operations'
phid baselines --recalculate --days 30
phid baselines --view anomalies
```

Investigations refresh AWS evidence by default; `--no-refresh` uses only stored evidence. Notes and recalculated baselines update the local database.

## HTML dashboard

Generate a dashboard after a scan, or regenerate it from the existing database without contacting AWS:

```sh
phid scan --html data/scan-report.html --output report.json
phid report --html data/scan-report.html
# Also supported for findings and foreground monitoring:
phid findings --html data/scan-report.html
phid agent --interval 300 --html data/scan-report.html
```

Open `data/scan-report.html` in a browser. The dashboard includes severity totals, **every stored finding**, resources, incidents, evidence, and the latest scan's coverage. Expand **Full details** for complete records. It is generated entirely in Python with embedded CSS: no JavaScript, server, CDN, or network access is needed to view it.

The HTML includes all retained database records across scan scopes, regardless of CLI query filters or pagination; JSON output retains the command's normal scope and filters. Coverage describes the latest scan, not all retained history. Empty databases and partial scans are explicitly represented.

`--html FILE` works with `scan`, `findings`, `report`, and `agent`. The parent directory must exist. The file is replaced atomically with owner-only permissions. Monitoring replaces it after every cycle, including a failed cycle, whose command result is shown alongside the last stored scan. JSON still goes to stdout or `--output`; use separate paths for HTML and JSON.

## Foreground monitoring

```sh
phid agent --interval 300
phid agent --once --scope s3
phid cycles
```

Ctrl-C stops monitoring after the current scan. Each cycle is persisted. `--output FILE` replaces the file with the latest result; without it, each cycle prints a JSON document to stdout.

## Output and exit codes

All results are JSON (`--json` is accepted explicitly). `--output FILE` writes with owner-only permissions. Errors go to stderr. Exit codes: 0 success, 1 operation failure, 2 invalid arguments, 130 interruption. A `PARTIAL` scan exits 0: inspect `coverage` to identify collection gaps. A failed `agent --once` exits 1.

CLI options override environment configuration. Configuration accepts flat JSON or nested YAML (`aws`, `storage`, `llm`, `agent`, `detection`). `PHI_CONFIG` selects a JSON configuration; `PHI_DB` selects the database. AWS region environment variables override JSON regions; `--regions` overrides them for collection. See `phid --man` for commands and filters.


## Command reference

| Command | Description |
|---------|-------------|
| `scan` | Collect AWS evidence; `--scope all\|s3\|databases\|logs` |
| `inventory` | List or inspect resources |
| `findings` | List or inspect findings; `--severity HIGH` |
| `evidence` | List or inspect evidence records |
| `data-map` | Show data lineage; `--dot FILE` for Graphviz |
| `iam` | Analyze IAM roles, principals, and excessive access |
| `exposure` | Show public, cross-account, or third-party exposure |
| `logs` | CloudWatch log group findings |
| `investigate` | Start an investigation review |
| `investigations` | List or inspect investigation reviews |
| `incidents` | List incidents |
| `incident` | Inspect an incident; `--note TEXT` persists a note |
| `baselines` | Behavioral baselines; `--recalculate --days N` |
| `ask` | Natural-language questions answered from stored evidence |
| `classify` | Detect PHI/PII in text; `--input FILE` |
| `controls` | Technical control observations |
| `health` | Local database and account status |
| `report` | Export all findings as HTML/JSON |
| `agent` | Repeated foreground scans; `--interval N` |
| `config-check` | Inspect resolved configuration (db, regions, LLM) |

## Local AI and evidence-driven investigation

Ollama must already be running locally; this tool never starts a server. Use an installed model:

```sh
phid ask "Who accessed patient data yesterday?" --llm ollama --model gemma3:4b
phid investigate --resource medical-bucket --no-refresh --config config/local-example.json
phid report --html data/scan-report.html --config config/local-example.json
phid llm-runs
phid classify 'MRN: 883122'
phid classify --input example.txt --llm ollama --model gemma3:4b
```

`config/local-example.json` supports separate `fast`, `classification`, `reasoning`, and `report` models. Only loopback Ollama addresses are accepted; proxies and redirects are disabled. Model output must reference supplied evidence IDs. Commentary remains advisory and is never promoted to verified evidence or executed as a command. Model run metadata is persisted without raw input payloads.

For inference inside the Python process, install `python -m pip install -e '.[local-ai]'` and use `--llm local --model /path/to/model.gguf`. Model downloads are never automatic. Deterministic operation (`--llm none`) remains the default.

Investigations use bounded queries for identity/session, related resource, network, and counter-evidence. The local planner may order these fixed templates; it cannot supply SQL, commands or AWS operations. Agent cycles triage high-severity behavioral findings and avoid repeating unchanged evidence.

## Discovery and analysis configuration

The default scan uses metadata and bounded telemetry. Optional configuration:

- `object_metadata: true` inventories bounded S3 keys/prefixes; `object_prefixes` restricts bucket prefixes.
- `config_history: true` collects configuration field changes and hashes, rather than raw historical configurations.
- `organizations: true` collects account IDs/state for ownership context.
- `db_samples` explicitly lists service, region, table and limit (1–10). DynamoDB sampling requires a separate narrowly scoped Scan permission. PostgreSQL/Aurora PostgreSQL and Redshift sampling require `python -m pip install -e '.[databases]'`, a `dsn_env`, `resource` ARN and optional `schema`/`columns`. The database transaction is read-only, with bounded rows, columns, cell lengths and statement timeout. No secrets are retrieved through AWS.
- `log_objects` explicitly lists region, bucket, key, format (`alb`, `s3-access`, or application text), and optional resource ARN. Reads are bounded by `sample_bytes` and need separately scoped S3 GetObject permission.
- `custom_patterns` entries may include `classification`; `classification_taxonomy` entries support `sensitive` and `sensitivity` (0–40). Stronger classifications survive later weaker observations.
- `approved_activity` contains identity/resource patterns, timezone-aware `from`/`to` and a reason. `expected_hours` maps identity ARNs to expected UTC hours. Approved CIDRs and time windows reduce noise; a new identity/IP alone does not establish an incident.
- `network_enrichment` maps destination IPs to optional ASN/country/VPC metadata supplied by the operator. No external enrichment calls occur.
- `detectors` supports `log_phi_detection`, `pii_detection`, `bulk_access_detection`, `unusual_identity_detection`, `data_exfiltration_detection`, and exact finding-type switches.
- Optional NLP uses an already installed spaCy model via `nlp_model` and the `.[nlp]` extra. No model download occurs during scans.

```sh
phid controls
phid data-map --dot data/lineage.dot
```

The graph includes candidate permissions, application routing, backups, encryption keys and observed copies. DOT can be rendered separately with Graphviz. The HTML report also includes relationships, investigations and control observations. Only complete scoped rescans close resolved configuration findings; historical behavior and incomplete scans do not erase findings.

Content sampling is skipped after the first agent cycle unless `sample_every_cycle` is true. Broader discovery remains bounded by page, resource and time budgets.

## Container

```sh
docker build -t phid .
docker run --rm phid --man
docker run --rm -v phi-data:/data -v "$HOME/.aws:/home/phi/.aws:ro" -e AWS_PROFILE=production phid scan
```

The container runs a CLI command and exits; it exposes no ports. Mounted AWS credentials must be readable by the container user.

## Validation and limitations

See [implementation and remaining limits](docs/implementation.md) for current coverage and [the historical audit](docs/python-requirements-audit.md) for the original gaps. Requirement-based Python tests replace obsolete HTTP/server test expectations.

```sh
python3 -m unittest discover -s tests_python -v
```

IAM policy matches represent candidate access, not full effective authorization. Relationships do not necessarily represent observed data movement. Missing telemetry does not establish absence of exposure, and findings do not confirm a breach. Review coverage and evidence before drawing conclusions.

Historical planning documents may describe the earlier implementation. Active requirements are Python CLI-only.

## License and commercial use

PHI/PII Security CLI (`phid` / `phi-security`) is **source-available**, not
OSI-approved Open Source. Original project material is licensed under
[PolyForm Noncommercial 1.0.0](LICENSE), with the copyright notice in [NOTICE](NOTICE).
You may use, study, modify, fork and distribute it for purposes permitted by that
license, preserving its required terms and notices.

Uses outside those permissions—including typical commercial internal security
operations, paid client assessments and commercial redistribution—require a
separate signed license from **Oleksandr Amirkhanov**. The license's express
permissions for listed organizations, including health organizations, still
apply; not every healthcare use requires a paid license.

Contact [license@amirkhanov.org](mailto:license@amirkhanov.org); see
[COMMERCIAL.md](COMMERCIAL.md) for scopes and how to request terms. Consulting,
implementation, customization and support may be arranged separately. Hiring a
consultant does not itself supply software rights. Copyright remains with the
applicable owners; no trademark rights are granted. Dependencies and local model
weights retain their own licenses.

Contributions require explicit acceptance of [CONTRIBUTING.md](CONTRIBUTING.md).

## Project website

Open `index.html` directly for the standalone landing page. It uses HTML and CSS
only, with no JavaScript, application server, or build step. Downloads link to
`dist/phid`, its SHA-256 checksum, and `dist/phid-2.0.0-source.tar.gz`.

For static hosting, publish the page together with `install.sh`, those download
artifacts, the linked legal documents, `README.md`, `config/example.json`, and
`docs/implementation.md`, `packaging/build_binary.py`, and
`packaging/smoke_binary.py`. Do not publish the repository's `data/` directory or
credentials. Replace `https://phid.amirkhanov.org` in the installation example with the
actual public site URL before publishing. No public repository URL is configured;
the source button downloads the included source archive.

The shell installer requires an explicit HTTPS `--base-url`, verifies the binary
against the hosted SHA-256 checksum, and installs to `$HOME/.local/bin` (override
with `PHID_INSTALL_DIR`). The available binary supports macOS Apple Silicon only.

The website uses a compact package-page layout with a release table and source
installation instructions for macOS Intel, Ubuntu, and Windows. Status badges
distinguish local verification from hosted CI (not configured). Only the macOS
Apple Silicon binary is currently available; other platform instructions do not
represent verified native builds.
