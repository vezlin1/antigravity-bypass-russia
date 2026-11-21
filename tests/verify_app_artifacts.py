"""Inspect disposable official App ASARs without executing or modifying the application."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    data = path.read_bytes()
    assert struct.unpack_from('<I', data)[0] == 4, 'Invalid ASAR'
    size = struct.unpack_from('<I', data, 4)[0] + 8
    header = json.loads(data[16:16 + struct.unpack_from('<I', data, 12)[0]])

    def walk(node, prefix=''):
        for name, value in node.get('files', {}).items():
            name = prefix + name
            if 'files' in value:
                yield from walk(value, name + '/')
            elif 'offset' in value:
                start = size + int(value['offset'])
                end = start + value['size']
                assert size <= start <= end <= len(data), name
                yield name, data[start:end]

    return data, dict(walk(header))


def verify(path, apps):
    data, entries = read(path)
    package = json.loads(entries['package.json'])
    version = package['version']
    pin = next((app for app in apps if app['version'] == version), None)
    assert pin is not None, f'{path}: App {version} is not pinned'
    assert hashlib.sha256(data).hexdigest() == pin['asar_sha256'], path
    assert package['name'] == 'antigravity' and package['main'] in entries, path
    print(f'PASS: App {version} ASAR hash, version, entry bounds and main entry', flush=True)
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('asar', type=Path, nargs='+')
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    pins = json.loads((ROOT / 'tests/upstream-versions.json').read_text(encoding='utf-8'))
    apps = [pins[label]['app'] for label in ('current', 'previous')]
    previous = read(args.previous)[1] if args.previous else None
    for path in args.asar:
        entries = verify(path, apps)
        if previous is not None:
            changed = [name for name in entries.keys() | previous.keys() if entries.get(name) != previous.get(name)]
            assert changed == ['package.json'], changed
            print('PASS: all archived App code is unchanged from previous version; package.json only')


if __name__ == '__main__':
    main()
