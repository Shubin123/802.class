#!/usr/bin/env python3
"""Install the current project on writable CM4 storage over SSH."""
import argparse
import json
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--path', default='/storage/802.class')
    p.add_argument('--include-field-data', action='store_true', help='Explicitly transfer private field captures and models; never pushes them to Git')
    p.add_argument('--test', action='store_true')
    args = p.parse_args()
    target = shlex.quote(args.path)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', args.host]
    subprocess.run(ssh + [f'mkdir -p {target}'], check=True)
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
    with tempfile.TemporaryFile() as transfer:
        with tarfile.open(fileobj=transfer, mode='w:gz') as archive:
            for name in names:
                if name and (ROOT / name).is_file():
                    archive.add(ROOT / name, arcname=name, recursive=False)
            if args.include_field_data:
                for folder in ('data/field/cm4', 'models'):
                    path = ROOT / folder
                    if path.exists():
                        archive.add(path, arcname=folder)
        transfer.seek(0)
        subprocess.run(ssh + [f'tar -xzf - -C {target}'], stdin=transfer, check=True)
    command = f'''set -eu
cd {target}
export UV_CACHE_DIR="$PWD/.cache"
UV="$PWD/.tools/uv-aarch64-unknown-linux-gnu/uv"
if [ ! -x "$UV" ]; then
    mkdir -p .tools
    curl --fail --location https://github.com/astral-sh/uv/releases/download/0.13.1/uv-aarch64-unknown-linux-gnu.tar.gz -o .tools/uv.tar.gz
    tar -xzf .tools/uv.tar.gz -C .tools
fi
if [ ! -x .venv/bin/python ]; then "$UV" venv --python /usr/bin/python3 .venv; fi
"$UV" pip install --torch-backend cpu --python .venv/bin/python -e '.[dev,display]'
.venv/bin/python -c 'import zipfile,pathlib; p=pathlib.Path("data/dataset_output_old/dataset.parquet"); p.exists() or zipfile.ZipFile(p.with_suffix(".parquet.zip")).extract("dataset.parquet",p.parent)'
.venv/bin/python -c 'import wifi_app,torch; print("Installed:",wifi_app.__file__,torch.__version__)'
'''
    if args.test:
        command += '.venv/bin/python -m pytest -q\n.venv/bin/python scripts/verify_install.py\n'
    subprocess.run(ssh + [command], check=True)
    print(json.dumps({'host': args.host, 'installed': args.path, 'field_data_transferred': args.include_field_data}))


if __name__ == '__main__':
    main()
