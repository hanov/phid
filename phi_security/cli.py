"""Command-line interface; all operations run in this Python process."""
import argparse
import json
import os
import signal
import sys
import time
import logging
from .engine import Engine, APIError
from .config import load

logger = logging.getLogger('phid')

MANUAL = """PHID(1)
NAME
    phid - read-only AWS PHI/PII investigation from the command line
SYNOPSIS
    phid COMMAND [VALUE] [OPTIONS]
    python3 -m phi_security COMMAND [VALUE] [OPTIONS]
    phid --man | phid man
DESCRIPTION
    Scans AWS using boto3 and stores redacted evidence in local SQLite.
    No application server or API layer. Optional inference uses an existing
    loopback Ollama process or an in-process GGUF model; no hosted inference.
    Stored-data queries work without AWS credentials or network access.
COMMANDS
    scan                  Collect AWS evidence (--scope all|s3|databases|logs).
    inventory [ID]        List resources or inspect a resource; --summary.
    findings [ID]         List findings or inspect one; --summary.
    evidence [ID]         List evidence or inspect one.
    data-map              Show relationships; --resource ID or --flow FROM TO.
    iam                   Analyze IAM; --view analysis|principals|excessive-access|
                          decrypt-access|cross-account. principals accepts VALUE
                          and --activity.
    exposure              Show exposure; --view public|cross-account|third-party.
    logs                  Show log findings; --view groups or --log-group NAME.
    investigate           Start a review with --resource, --identity or --trigger.
                          --no-refresh uses stored evidence only.
    investigations [ID]   List reviews or inspect one; --view timeline|hypotheses.
    incidents             List incidents.
    incident ID           Inspect an incident; --view evidence|timeline;
                          --note TEXT persists a redacted local note.
    baselines [ID]        Show baselines; --view anomalies; --recalculate
                          [--days 2..90] [--principal ID].
    classifications       Show classification taxonomy and detection patterns.
    ask QUESTION          Answer supported access, inventory, log and movement
                          questions from stored evidence; optional local commentary.
                          yesterday/today use UTC; unknown questions use search.
    classify TEXT         Detect sensitive text; --input FILE instead of TEXT
                          reads up to 64 KiB. Raw text is not stored.
    controls              Technical control observations (not legal compliance).
    llm-runs              Inspect persisted local inference audit records.
    agent                 Repeated foreground scans; --interval 30..86400,
                          --once for one cycle; Ctrl-C stops after current scan.
    cycles                Show persisted agent cycle history.
    health                Show local database/account/last-scan status.
    report                Export all stored findings and supporting records.
                          No AWS calls; combine with --html FILE.
OPTIONS
    --config FILE         JSON or YAML configuration (overrides PHI_CONFIG).
    --llm PROVIDER        none (default), ollama, or local (in-process GGUF).
    --model NAME          Local Ollama model name or GGUF file path.
                          Overrides per-role models for this invocation.
    --input FILE          UTF-8 input for classify; maximum 64 KiB.
    --dot FILE            data-map only: write Graphviz DOT relationships.
    --db FILE             SQLite path (overrides PHI_DB).
    --output FILE         Write JSON to a private file instead of stdout.
    --html FILE           Write an offline HTML/CSS dashboard (no JavaScript).
                          Supported by scan, findings, report and agent. Includes
                          ALL stored findings, resources, incidents and evidence,
                          ignoring pagination/query filters; latest scan coverage.
                          Expand Full details for complete records. Existing FILE
                          is replaced with owner-only permissions; parent must exist.
                          agent refreshes it after each cycle, including failures.
                          JSON output continues; --output must use a different file.
    --json                Explicit JSON output (already the default).
    --regions LIST        Comma-separated AWS regions for collection.
    --from TIME --to TIME  Evidence/collection time range; --to requires --from.
    --classification X    Classification filter.
    --severity X --status X --type X --source X --risk-level X
                          Stored-record filters where supported.
    --page N --limit N     Inventory pagination (limit 1..1000; default 20).
    --incident-id ID       Evidence belonging to an incident.
    --investigation-id ID  Evidence belonging to a review.
    -h, --help             Show argument help.
    --man                 Print this manual without opening a database.
    --version             Print the version.
    --license             Print license and bundled third-party notices.
                          Standalone builds include core and database adapters;
                          optional spaCy/GGUF require a Python source install.
ENVIRONMENT
    AWS_PROFILE, AWS_REGION, AWS_DEFAULT_REGION, AWS_REGIONS and standard
    boto3 credential variables; PHI_CONFIG and PHI_DB. .env is not auto-loaded.
EXAMPLES
    phid scan --regions us-east-1 --output report.json
    phid scan --html data/scan-report.html --output report.json
    phid report --html data/scan-report.html
    phid scan --scope logs --from 24h
    phid inventory --classification PHI_HIGH --limit 100
    phid investigate --resource medical-bucket --no-refresh
    phid investigations inv-123 --view timeline
    phid incident inc-123 --note 'Reviewed by operations'
    phid ask 'Who accessed patient data yesterday?'
    phid ask 'Was PHI written into logs today?' --llm ollama --model qwen2.5:3b
    phid classify --input example.txt
    phid controls
    phid data-map --dot data/lineage.dot
    phid agent --once --scope s3
EXIT STATUS
    0 success (a PARTIAL scan has coverage gaps; inspect its coverage field).
    1 operation failure. 2 invalid command-line arguments. 130 interrupted.
LIMITATIONS
    Read-only AWS collection; notes and baselines modify only the local database.
    Local model commentary is advisory; evidence references are validated.
    Investigations expand stored evidence using bounded read-only templates.
    Agent triage avoids repeating the same evidence and samples content only
    on its first cycle unless sample_every_cycle is explicitly enabled.
    Sampling: explicit S3 keys, DynamoDB tables, or PostgreSQL/Redshift tables;
    no direct MySQL/DocumentDB/OpenSearch record sampling.
    IAM relationships are candidate access, not proof of effective permissions.
    Missing telemetry is not proof of absence; findings do not confirm a breach.
"""


def _tty_summary(command, result):
    """Concise human-readable summary for interactive terminal runs."""
    lines = []
    if command == 'scan':
        s = result.get('summary', {})
        sev = {}
        for f in result.get('findings', []):
            k = f.get('severity', 'UNKNOWN')
            sev[k] = sev.get(k, 0) + 1
        cov = result.get('coverage', [])
        collected = sum(1 for c in cov if c.get('status') == 'COLLECTED')
        other = len(cov) - collected
        lines.append(f"{result.get('status')}  {result.get('scanId')}  account={result.get('account', '?')}")
        lines.append(f"  resources  {s.get('total', 0)}  (phi={s.get('withPhi', 0)}  pii={s.get('withPii', 0)}  public={s.get('publiclyExposed', 0)}  unencrypted={s.get('unencrypted', 0)})")
        lines.append(f"  findings   {s.get('findingsCount', 0)}  (critical={sev.get('CRITICAL', 0)}  high={sev.get('HIGH', 0)}  medium={sev.get('MEDIUM', 0)}  low={sev.get('LOW', 0)})")
        lines.append(f"  coverage   {collected} collected  {other} other  events={result.get('eventsScanned', 0)}")
        if result.get('status') == 'PARTIAL':
            missing = [c.get('service', '') for c in cov if c.get('status') not in ('COLLECTED', 'LIMITATION')]
            if missing:
                lines.append(f"  gaps       {', '.join(dict.fromkeys(missing))}")
    elif command == 'health':
        lines.append(f"status={result.get('status')}  account={result.get('account', 'none')}  version={result.get('version', '?')}")
        last = result.get('lastScan') or {}
        if last:
            lines.append(f"  last scan  {last.get('status')}  {last.get('completedAt', '')[:19]}")
    elif command in ('findings', 'inventory'):
        total = result.get('total', 0)
        lines.append(f"{command}  total={total}")
        for item in result.get('findings', result.get('data', []))[:5]:
            sev = item.get('severity', '')
            label = f"  [{sev}]  {item.get('type', item.get('classification', ''))}  {item.get('resource', item.get('arn', ''))}"
            lines.append(label)
        if total > 5:
            lines.append(f"  ... {total - 5} more (use --output FILE for full JSON)")
    elif command == 'ask':
        ans = result.get('answer') or result.get('summary', '')
        lines.append('ask  ' + (ans[:120] if ans else '(no answer)'))
    else:
        # For all other commands: fall through to JSON
        return False
    print('\n'.join(lines))
    return True


def emit(value, output=None, stream=None):
    text = json.dumps(value, indent=2, default=str) + '\n'
    if output:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
    else:
        print(text, end='', file=stream or sys.stdout)


def parser_for_cli():
    parser = argparse.ArgumentParser(prog='phid', description='Python-only AWS PHI/PII investigator', epilog='Use --man for the complete manual.')
    parser.add_argument('--version', action='version', version='phid 2.0.0')
    parser.add_argument('--license', action='store_true', help='print bundled license and copyright notices')
    parser.add_argument('--man', action='store_true', help='print full manual and exit')
    parser.add_argument('command', nargs='?', choices=['man', 'scan', 'inventory', 'data-map', 'exposure', 'iam', 'logs', 'investigate', 'investigations', 'incidents', 'incident', 'findings', 'evidence', 'baselines', 'classifications', 'ask', 'agent', 'cycles', 'health', 'report', 'controls', 'llm-runs', 'classify', 'config-check'])
    parser.add_argument('value', nargs='?', help='record ID or quoted question')
    for flag in ['resource', 'identity', 'classification', 'regions', 'output', 'config', 'db', 'view', 'severity', 'status', 'type', 'source', 'risk-level', 'incident-id', 'investigation-id', 'trigger', 'note', 'principal', 'log-group', 'skip']:
        parser.add_argument('--' + flag)
    parser.add_argument('--llm', choices=['none', 'ollama', 'local'], help='local inference adapter; never starts a server')
    parser.add_argument('--model', help='local Ollama model name or GGUF path')
    parser.add_argument('--input', metavar='FILE', help='UTF-8 input for classify (max 64 KiB)')
    parser.add_argument('--dot', metavar='FILE', help='write data-map as Graphviz DOT')
    parser.add_argument('--html', metavar='FILE', help='write a self-contained dashboard of all stored findings (scan, findings, report, agent)')
    parser.add_argument('--from', dest='from_time')
    parser.add_argument('--to', dest='to_time')
    parser.add_argument('--scope', choices=['all', 's3', 'databases', 'logs'], default='all')
    parser.add_argument('--interval', type=int)
    parser.add_argument('--page', type=int, default=1)
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--days', type=int)
    parser.add_argument('--flow', nargs=2, metavar=('FROM', 'TO'))
    for flag in ['once', 'json', 'summary', 'activity', 'recalculate', 'no-refresh', 'no-tui', 'dry-run']:
        parser.add_argument('--' + flag, action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true', help='enable debug-level logging to stderr')
    return parser


def execute(engine, args, params):
    command, value = args.command, args.value
    if command == 'classify':
        from .privacy import detect, fingerprint
        if args.input:
            with open(args.input, 'rb') as handle:
                raw = handle.read(65537)
            if len(raw) > 65536: raise ValueError('Classification input exceeds 64 KiB')
            value = raw.decode('utf-8')
        result = detect(value, engine.config['custom_patterns'], engine.config.get('pattern_classifications'))
        result['contentHash'] = fingerprint(value)
        if engine.config['llm']['provider'] != 'none':
            from .llm import Router
            result['modelCommentary'] = Router(engine.config, engine.store).query('Explain these detector classifications without inventing data.', [{'id': 'classification-' + result['contentHash'][:20], 'classification': result['classification'], 'detectedTypes': result['detectedTypes']}], role='classification')
        return result
    if command == 'controls':
        from .controls import assess
        return assess(engine.all('resources'), engine.all('findings'), engine.all('evidence'))
    if command == 'llm-runs':
        return {'runs': engine.all('llm_runs')}
    if command == 'report':
        from .report import snapshot
        result = snapshot(engine)
        if engine.config['llm']['provider'] != 'none':
            from .llm import Router
            result['modelCommentary'] = Router(engine.config, engine.store).query('Summarize the privacy evidence and its limitations.', result['evidence'], role='report')
        return result
    if command == 'config-check':
        return {'status': 'ok', 'db': engine.config.get('db'), 'regions': engine.config.get('regions', []), 'llm': engine.config.get('llm', {}).get('provider', 'none'), 'version': '2.0.0'}
    if command == 'scan':
        return engine.scan(params, args.scope)
    if command == 'investigate':
        return engine.investigate(params)
    if command == 'ask':
        from .questions import ask
        return ask(engine, value, params)
    if command == 'classifications':
        from .privacy import PATTERNS
        return {'taxonomy': engine.config.get('classification_taxonomy', {}), 'patterns': list(PATTERNS)}
    if command == 'incident':
        return engine.incident_api('POST' if args.note else 'GET', [value] + (['notes'] if args.note else [args.view] if args.view else []), params)
    if command == 'data-map':
        return engine.graph_api(['flow', *args.flow] if args.flow else ['resource', args.resource] if args.resource else [])
    if command == 'iam':
        return engine.iam_api([args.view or 'analysis'] + ([value] if value else []) + (['activity'] if args.activity else []), params)
    if command == 'exposure':
        return engine.exposure_api([args.view] if args.view else [], params)
    if command == 'logs':
        tail = ['groups', args.log_group, 'findings'] if args.log_group else [args.view or 'findings']
        return engine.logs_api('GET', tail, params)
    # This is an in-process query dispatcher; it opens no socket or server.
    group = {'investigations': 'investigate', 'cycles': 'agent-cycles'}.get(command, command)
    tail = 'summary' if args.summary else 'recalculate' if args.recalculate else value
    if args.view:
        tail = '/'.join(filter(None, [tail, args.view]))
    return engine.dispatch('POST' if args.recalculate else 'GET', '/' + group + ('/' + tail if tail else ''), params)


def main(argv=None):
    parser = parser_for_cli()
    args = parser.parse_args(argv)
    if args.license:
        from pathlib import Path
        root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))
        legal = root / 'legal' if getattr(sys, 'frozen', False) else root
        for name in ['NOTICE', 'LICENSE', 'THIRD-PARTY-NOTICES.txt']:
            path = legal / name
            if path.exists(): print(path.read_text())
        return 0
    if args.man or args.command == 'man':
        print(MANUAL)
        return 0
    if not args.command:
        parser.error('a command is required (see --man)')
    if args.command == 'classify' and bool(args.value) == bool(args.input):
        parser.error('classify requires either quoted text or --input FILE')
    if args.input and args.command != 'classify':
        parser.error('--input requires classify')
    if args.dot and args.command != 'data-map':
        parser.error('--dot requires data-map')
    if args.html and args.command not in ['scan', 'findings', 'report', 'agent']:
        parser.error('--html requires scan, findings, report, or agent')
    if args.html and args.output:
        from pathlib import Path
        if Path(args.html).resolve() == Path(args.output).resolve():
            parser.error('--html and --output must use different files')
    if args.command in ['ask', 'incident'] and not args.value:
        parser.error(args.command + ' requires a value')
    if args.to_time and not args.from_time:
        parser.error('--to requires --from')
    if (args.interval is not None and not 30 <= args.interval <= 86400) or not 1 <= args.limit <= 1000 or args.page < 1:
        parser.error('interval must be 30..86400, limit 1..1000, and page positive')
    if args.days is not None and not 2 <= args.days <= 90:
        parser.error('--days must be 2..90')
    views = {'iam': ['analysis', 'principals', 'excessive-access', 'decrypt-access', 'cross-account'], 'exposure': ['public', 'cross-account', 'third-party'], 'logs': ['groups', 'findings'], 'incident': ['evidence', 'timeline'], 'investigations': ['timeline', 'hypotheses'], 'baselines': ['anomalies']}
    if args.view and args.view not in views.get(args.command, []):
        parser.error('unsupported --view for this command')
    if args.command == 'investigations' and args.view and not args.value:
        parser.error('--view requires an investigation ID')
    if args.recalculate and args.command != 'baselines':
        parser.error('--recalculate requires baselines')
    if args.summary and args.command not in ['inventory', 'findings']:
        parser.error('--summary requires inventory or findings')
    if args.activity and (args.command != 'iam' or args.view != 'principals' or not args.value):
        parser.error('--activity requires iam ID --view principals')
    if args.note and args.command != 'incident':
        parser.error('--note requires incident ID')
    if args.flow and args.command != 'data-map':
        parser.error('--flow requires data-map')
    params = {k: getattr(args, k) for k in ['resource', 'identity', 'classification', 'severity', 'status', 'type', 'source', 'trigger', 'note'] if getattr(args, k)}
    params.update(page=args.page, limit=args.limit)
    for option, key in [('risk_level', 'riskLevel'), ('incident_id', 'incidentId'), ('investigation_id', 'investigationId'), ('principal', 'principalId'), ('days', 'days')]:
        if getattr(args, option) is not None:
            params[key] = getattr(args, option)
    if args.regions:
        params['regions'] = [r.strip() for r in args.regions.split(',')]
    if args.from_time:
        params['timeRange'] = {'from': args.from_time, **({'to': args.to_time} if args.to_time else {})}
        if args.command not in ['scan', 'agent', 'investigate']:
            params.update(params['timeRange'])
    if args.no_refresh:
        params['refresh'] = False
    if getattr(args, 'dry_run', False):
        params['dryRun'] = True
    engine = None
    handlers = {}
    try:
        _log_level = logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO
        logging.basicConfig(level=_log_level, format='%(message)s', stream=sys.stderr)
        config = load(args.config, args.db)
        if args.llm: config['llm']['provider'] = args.llm
        if args.model: config['llm']['model'] = args.model; config['llm']['models'] = {}
        args.interval = args.interval if args.interval is not None else config.get('agent_interval', 300)
        from pathlib import Path
        outputs = [p for p in [args.output, args.html, args.dot] if p]
        protected = [config['db'], config['db'] + '-wal', config['db'] + '-shm', args.config or os.environ.get('PHI_CONFIG'), args.input]
        def same_path(a, b):
            return Path(a).resolve() == Path(b).resolve() or (Path(a).exists() and Path(b).exists() and os.path.samefile(a, b))
        for index, path in enumerate(outputs):
            if any(p and same_path(path, p) for p in protected + outputs[:index]):
                parser.error('Output files must be distinct and must not overwrite inputs, database, or configuration')
        engine = Engine(config)
        if getattr(args, 'skip', None) and args.command in ('scan', 'agent'):
            config['skip_services'] = [s.strip() for s in args.skip.split(',') if s.strip()]
        logger.info('%s  db=%s', args.command, config['db'])
        if args.command != 'agent':
            progress = None
            if args.command == 'scan' and sys.stdin.isatty() and not args.json and not args.no_tui:
                from . import tui as _tui
                scope, skip = _tui.launch(config)   # shows curses UI; raises SystemExit on Q
                args.scope = scope
                config['skip_services'] = skip      # same dict as engine.config
                print()                             # blank line after curses teardown
                progress = _tui.ScanProgress()
                progress.start()
            _t0 = time.monotonic()
            try:
                result = execute(engine, args, params)
            finally:
                if progress:
                    progress.stop()
            if args.command == 'scan':
                logger.info('elapsed  %.1fs', time.monotonic() - _t0)
            if args.dot:
                from .topology import dot
                fd = os.open(args.dot, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(dot(engine.graph()))
            if args.html:
                from .report import snapshot, write_dashboard
                write_dashboard(args.html, result if args.command == 'report' else snapshot(engine), None if args.command == 'report' else result)
            if not args.output and not args.json and sys.stdout.isatty() and _tty_summary(args.command, result):
                pass
            else:
                emit(result, args.output)
            return 0
        running = [True]
        cycle_number = 0
        original_sampling = engine.config.get('sample_objects', False)
        original_db_samples = engine.config.get('db_samples', [])
        for sig in [signal.SIGINT, signal.SIGTERM]:
            handlers[sig] = signal.signal(sig, lambda *_: running.__setitem__(0, False))
        while running[0]:
            import uuid
            from .storage import now
            cycle = {'cycleId': 'cycle-' + uuid.uuid4().hex, 'startedAt': now()}
            failed = False
            logger.info('agent  cycle=%d  scope=%s', cycle_number + 1, args.scope)
            try:
                engine.config['sample_objects'] = original_sampling if cycle_number == 0 or engine.config.get('sample_every_cycle') else False
                engine.config['db_samples'] = original_db_samples if cycle_number == 0 or engine.config.get('sample_every_cycle') else []
                result = engine.scan(params, args.scope)
                from .agent import triage
                cycle['investigations'] = triage(engine, result)
                cycle.update(status=result['status'], scanId=result['scanId'], newFindings=result['summary']['findingsCount'])
            except Exception as exc:
                failed = True
                result = {'status': 'FAILED', 'errorType': type(exc).__name__}
                cycle.update(result)
            cycle_number += 1
            cycle['completedAt'] = now()
            engine.dispatch('POST', '/record-cycle', cycle)
            if args.html:
                from .report import snapshot, write_dashboard
                write_dashboard(args.html, snapshot(engine), result)
            emit(result, args.output)
            if args.once:
                return 1 if failed else 0
            deadline = time.monotonic() + args.interval
            while running[0] and time.monotonic() < deadline:
                time.sleep(max(0, min(1, deadline - time.monotonic())))
        return 0
    except APIError as exc:
        emit({'error': str(exc), 'status': exc.status}, stream=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        emit({'error': 'Operation failed; check configuration, AWS access, and file permissions', 'errorType': type(exc).__name__}, stream=sys.stderr)
        return 1
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        if engine:
            engine.store.close()


if __name__ == '__main__':
    sys.exit(main())
