#!/usr/bin/env python3
"""Fetch every open-alert page; an inaccessible or incomplete inventory is a failure."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

def collect(repository, request_page):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid repository')
    alerts = []; seen = set()
    for page in range(1, 101):
        batch = request_page(f'https://api.github.com/repos/{repository}/dependabot/alerts?state=open&per_page=100&page={page}')
        if not isinstance(batch, list) or len(batch) > 100: raise ValueError('invalid alerts page')
        for alert in batch:
            if not isinstance(alert, dict) or not isinstance(alert.get('number'), int) or isinstance(alert['number'], bool):
                raise ValueError('invalid alert identity')
            if alert['number'] in seen: raise ValueError('duplicate alert across pages; retry inventory')
            seen.add(alert['number']); alerts.append(alert)
        if len(batch) < 100: return alerts, page
    raise ValueError('alerts pagination limit exceeded')

def fetch(repository, token):
    if not token: raise ValueError('PREFLIGHT_TOKEN with Dependabot alerts read access is required')
    def request_page(url):
        request = urllib.request.Request(url, headers={'Authorization':'Bearer '+token,
            'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200: raise ValueError('alerts endpoint did not return 200')
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024: raise ValueError('alerts page too large')
            return json.loads(data)
    return collect(repository, request_page)

def write_inventory(alerts, pages, repository, output, receipt, *, collected_at=None):
    data = (json.dumps(alerts, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    output.write_bytes(data)
    receipt.write_text(json.dumps({'version':2,'complete':True,'repository':repository,'pages':pages,
        'query':{'state':'open','perPage':100}, 'collectorVersion':2,
        'collectedAtUtc': collected_at or datetime.now(timezone.utc).isoformat(),
        'execution':{name:os.environ.get(name) for name in ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA']},
        'alertCount':len(alerts),'sha256':hashlib.sha256(data).hexdigest()},indent=2)+'\n',encoding='utf-8')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--repository',required=True)
    parser.add_argument('--output',type=Path,required=True); parser.add_argument('--receipt',type=Path,required=True)
    args = parser.parse_args()
    try:
        alerts, pages = fetch(args.repository, os.environ.get('GH_TOKEN',''))
        write_inventory(alerts,pages,args.repository,args.output,args.receipt)
        print(f'Complete Dependabot inventory: {len(alerts)} alerts, {pages} pages')
    except Exception as error:
        # Do not echo remote bodies, URLs or exception fragments into CI logs.
        print(f'Dependabot inventory unavailable ({type(error).__name__}); publication blocked',file=sys.stderr)
        sys.exit(1)
