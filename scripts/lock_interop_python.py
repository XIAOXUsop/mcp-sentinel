#!/usr/bin/env python3
"""Freeze hashes for all published artifacts of each exact validation dependency."""
import concurrent.futures
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def hashes(line):
    pin, *marker = line.partition(';')[::2]
    name, version = pin.strip().split('==')
    url = f'https://pypi.org/pypi/{name}/{version}/json'
    with urllib.request.urlopen(url, timeout=30) as response:
        doc = json.load(response)
    values = sorted({item['digests']['sha256'] for item in doc['urls'] if not item.get('yanked')})
    if not values: raise ValueError(f'no immutable artifacts for {name}')
    head = f'{name}=={version}' + ('; '+marker[0].strip() if marker and marker[0].strip() else '')
    return head + ' \\\n' + ' \\\n'.join('    --hash=sha256:'+value for value in values)


if __name__=='__main__':
    pins = (ROOT/'validation/interop/requirements-pins.txt').read_text(encoding='utf-8').splitlines()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        entries = list(executor.map(hashes, pins))
    (ROOT/'validation/interop/requirements-lock.txt').write_text('\n'.join(entries)+'\n',encoding='utf-8',newline='\n')
    print(f'Locked {len(entries)} exact distributions with artifact hashes.')
