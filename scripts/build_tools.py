#!/usr/bin/env python3
"""Build both dependency-free tools with explicit source metadata."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

TARGETS = {
    'linux-amd64': ('linux', 'amd64', {}),
    'linux-arm64': ('linux', 'arm64', {}),
    'linux-armv7': ('linux', 'arm', {'GOARM': '7'}),
    'linux-mipsle-softfloat': ('linux', 'mipsle', {'GOMIPS': 'softfloat'}),
    'linux-mips-softfloat': ('linux', 'mips', {'GOMIPS': 'softfloat'}),
    'windows-amd64': ('windows', 'amd64', {}),
    'windows-arm64': ('windows', 'arm64', {}),
    'darwin-amd64': ('darwin', 'amd64', {}),
    'darwin-arm64': ('darwin', 'arm64', {}),
    'android-arm64': ('android', 'arm64', {}),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=['all', *TARGETS], default='all')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    for value in (args.version, args.commit):
        if not value or any(c.isspace() for c in value):
            parser.error('version and commit must be nonempty and contain no whitespace')
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    toolchain = subprocess.check_output(['go', 'version'], text=True).strip()
    targets = TARGETS if args.target == 'all' else [args.target]
    for target in targets:
        goos, goarch, extra = TARGETS[target]
        environment = os.environ.copy()
        for name in ('GOARM', 'GOMIPS', 'GOAMD64', 'GOEXPERIMENT', 'GOFLAGS'):
            environment.pop(name, None)
        environment.update(CGO_ENABLED='0', GOOS=goos, GOARCH=goarch, **extra)
        flags = (f'-s -w -X github.com/PoriyaVali/mirage/internal/version.Version={args.version} '
                 f'-X github.com/PoriyaVali/mirage/internal/version.Commit={args.commit}')
        files = []
        for tool in ('miragecheck', 'sweep'):
            destination = output / (f'{tool}-{target}' + ('.exe' if goos == 'windows' else ''))
            subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags', flags,
                            '-o', str(destination), f'./cmd/{tool}'], cwd=root,
                           env=environment, check=True)
            print(destination.name, flush=True)
            files.append({'name': destination.name, 'target': target,
                          'bytes': destination.stat().st_size,
                          'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                          'toolchain': toolchain})
        stamp = {'version': args.version, 'commit': args.commit, 'files': files}
        (output / f'build-{target}.json').write_text(json.dumps(stamp, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
