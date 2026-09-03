"""Offline acceptance checks for a built phid executable, using temporary data."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='phid-smoke-') as directory:
    db = str(Path(directory) / 'evidence.db')
    def run(*args, expected=0):
        result = subprocess.run([binary, *args], cwd=directory, text=True, capture_output=True, timeout=45)
        if result.returncode != expected:
            raise AssertionError(f'{args}: {result.returncode}: {result.stderr}')
        print('PASS:', args[0], flush=True)
        return result.stdout
    assert run('--version').strip() == 'phid 2.0.0'
    assert 'usage: phid' in run('--help')
    assert 'PHID(1)' in run('--man')
    notices = run('--license')
    assert 'license@amirkhanov.org' in notices
    assert 'PolyForm Noncommercial License 1.0.0' in notices
    assert 'botocore' in notices
    assert not Path(db).exists()
    assert json.loads(run('health', '--db', db))['status'] == 'ok'
    assert json.loads(run('classify', 'MRN: 12345', '--db', db))['classification'] == 'PHI_HIGH'
    assert json.loads(run('inventory', '--db', db))['pagination']['total'] == 0
    config = Path(directory) / 'config.yaml'
    config.write_text('aws:\n  regions: [us-east-1]\nllm:\n  provider: none\n')
    run('health', '--db', db, '--config', str(config))
    report = Path(directory) / 'report.html'
    run('report', '--db', db, '--html', str(report))
    assert 'All findings (0)' in report.read_text()
    assert report.stat().st_mode & 0o777 == 0o600
    run('not-a-command', expected=2)
print('PASS: native binary version, help, manual, licenses, SQLite, classification, inventory, YAML, HTML export, and argument errors.')
