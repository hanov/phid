"""Build the native phid CLI with PyInstaller from the current source tree.

Run in an environment containing pyinstaller and this project's [databases] extra.
Optional in-process GGUF and spaCy engines are excluded; local Ollama is supported.
"""
from importlib import metadata
from pathlib import Path
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build' / 'binary'
WORK.mkdir(parents=True, exist_ok=True)
LEGAL = WORK / 'legal'
LEGAL.mkdir(exist_ok=True)
for name in ['LICENSE', 'NOTICE', 'COMMERCIAL.md', 'LICENSE-COMMERCIAL.md', 'CONTRIBUTING.md']:
    shutil.copy2(ROOT / name, LEGAL / name)
notices = []
for package in ['boto3', 'botocore', 's3transfer', 'jmespath', 'python-dateutil', 'six', 'urllib3', 'PyYAML', 'psycopg', 'psycopg-binary', 'typing_extensions', 'packaging', 'altgraph', 'pyinstaller', 'pyinstaller-hooks-contrib']:
    try:
        dist = metadata.distribution(package)
    except metadata.PackageNotFoundError:
        continue
    texts = []
    for item in dist.files or []:
        name = str(item)
        if any(part in Path(name).name.lower() for part in ['license', 'copying', 'notice']) and '.dist-info/' in name:
            path = Path(dist.locate_file(item))
            if path.is_file():
                texts.append(name + '\n' + path.read_text(errors='replace'))
    notices.append(f'{package} {dist.version}\n' + '\n'.join(texts))
# Include the Python interpreter's own license text.
python_license = Path(sys.base_prefix) / 'LICENSE.txt'
if python_license.exists():
    notices.append('Python interpreter\n' + python_license.read_text())
else:
    license._Printer__setup()
    notices.append('Python interpreter\n' + '\n'.join(license._Printer__lines))
(LEGAL / 'THIRD-PARTY-NOTICES.txt').write_text('\n\n'.join(notices))
args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile',
        '--name', 'phid', '--paths', str(ROOT), '--distpath', str(ROOT / 'dist'),
        '--workpath', str(WORK / 'pyinstaller'), '--specpath', str(WORK),
        '--additional-hooks-dir', str(ROOT / 'packaging' / 'hooks'), '--collect-data', 'boto3',
        '--collect-all', 'psycopg', '--collect-all', 'psycopg_binary',
        '--copy-metadata', 'phi-security', '--add-data', str(LEGAL) + os.pathsep + 'legal',
        '--exclude-module', 'llama_cpp', '--exclude-module', 'spacy',
        str(ROOT / 'packaging' / 'phid_entry.py')]
env = dict(os.environ, PYINSTALLER_CONFIG_DIR=str(WORK / 'cache'))
subprocess.run(args, cwd=ROOT, env=env, check=True)
print('Built:', ROOT / 'dist' / 'phid')
