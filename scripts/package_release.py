#!/usr/bin/env python3
"""Create or verify the 20-tool release manifest and SHA-256 checksums."""
import argparse
import hashlib
import json
from pathlib import Path

from build_tools import TARGETS


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--commit')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    root = args.directory.resolve()
    expected = sorted(f'{tool}-{target}' + ('.exe' if TARGETS[target][0] == 'windows' else '')
                      for target in TARGETS for tool in ('miragecheck', 'sweep'))
    if args.verify:
        manifest = json.loads((root / 'MANIFEST.json').read_text(encoding='utf-8'))
        if sorted(item['name'] for item in manifest['files']) != expected:
            raise SystemExit('manifest does not contain exactly the expected 20 binaries')
        for item in manifest['files']:
            path = root / item['name']
            if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
                raise SystemExit(f'bad manifest entry: {path.name}')
        lines = (root / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        expected_checksums = expected + ['MANIFEST.json']
        if len(lines) != len(expected_checksums):
            raise SystemExit('unexpected checksum count')
        names = []
        for line in lines:
            sha, name = line.split('  ', 1)
            if name not in expected_checksums or digest(root / name) != sha:
                raise SystemExit(f'bad checksum entry: {name}')
            names.append(name)
        if sorted(names) != sorted(expected_checksums):
            raise SystemExit('duplicate or missing checksums')
        print('Verified 20 binaries, manifest and 21 SHA-256 checksums')
        return
    if not args.version or not args.commit:
        parser.error('--version and --commit are required when creating a package')
    files = []
    for target in TARGETS:
        stamp = json.loads((root / f'build-{target}.json').read_text(encoding='utf-8'))
        if stamp['version'] != args.version or stamp['commit'] != args.commit:
            raise SystemExit(f'mixed source metadata: {target}')
        for tool in ('miragecheck', 'sweep'):
            name = f'{tool}-{target}' + ('.exe' if TARGETS[target][0] == 'windows' else '')
            path = root / name
            entry = next(item for item in stamp['files'] if item['name'] == name)
            if entry['bytes'] != path.stat().st_size or entry['sha256'] != digest(path):
                raise SystemExit(f'binary changed after build: {name}')
            files.append(entry)
    manifest = {'version': args.version, 'commit': args.commit,
                'files': sorted(files, key=lambda item: item['name'])}
    (root / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    sums = [f'{digest(root / name)}  {name}\n' for name in expected + ['MANIFEST.json']]
    (root / 'SHA256SUMS').write_text(''.join(sums), encoding='utf-8')
    print('Packaged 20 binaries and manifest; SHA256SUMS excludes itself')


if __name__ == '__main__':
    main()
