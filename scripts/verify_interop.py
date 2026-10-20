#!/usr/bin/env python3
"""Exercise pinned public MCP implementations against independent wire evidence."""
from __future__ import annotations
import argparse
import contextlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

import jsonschema
import check_sarif_schema
from interop_support import ROOT, FIELDS, RawClient, OwnedProcess, free_port, wait_port, java_command, load, run, save, sha, source_identity


def tool_fields(tool):
    return {k: tool.get(k, '' if k in ('name','title','description') else {}) for k in FIELDS}


def validate_report(path, sarif):
    report = load(path)
    jsonschema.Draft202012Validator(load(ROOT/'schemas/scan-report-v3.schema.json')).validate(report)
    schema = check_sarif_schema.load_schema()
    jsonschema.validators.validator_for(schema)(schema).validate(load(sarif))
    return report


def verify(args):
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    jar = args.jar.resolve(); java = java_command(jar)
    manifest = load(ROOT/'validation/interop/manifest.json')
    for lock in manifest['dependencyLocks'].values():
        assert sha(ROOT/lock['path'])==lock['sha256'], 'dependency lock differs from frozen inventory'
    node = shutil.which('node'); assert node, 'Node.js 24 is required'
    installed = ROOT/'validation/interop/node_modules'
    for service in manifest['services']:
        if service['id'] != 'git':
            assert load(installed/service['package']/'package.json')['version'] == service['version']
    import importlib.metadata
    assert importlib.metadata.version('mcp-server-git') == next(s['version'] for s in manifest['services'] if s['id']=='git')
    repo = out/'allowed files 空格'; repo.mkdir(exist_ok=True)
    run(['git','init',str(repo)], out/'prepare-git')
    configs = {
        'filesystem-stdio': {'server':'interop-filesystem','command':node,'args':[str(installed/'@modelcontextprotocol/server-filesystem/dist/index.js'), str(repo)]},
        'git-stdio': {'server':'interop-git','command':sys.executable,'args':['-m','mcp_server_git','--repository',str(repo)]},
        'playwright-stdio': {'server':'interop-playwright','command':node,'args':[str(installed/'@playwright/mcp/cli.js'),'--headless','--isolated']},
    }
    port = free_port()
    configs['playwright-http'] = {'server':'interop-playwright','transport':'streamable-http','url':f'http://127.0.0.1:{port}/mcp'}
    javac = str(Path(java[0]).with_name('javac.exe' if os.name=='nt' else 'javac')) if os.environ.get('JAVA_HOME') else 'javac'
    classes = out/'classes'; classes.mkdir(exist_ok=True)
    run([javac,'-encoding','UTF-8','-cp',str(jar),'-d',str(classes),str(ROOT/'scripts/ValidationFixtures.java'),str(ROOT/'scripts/CollectionMetadata.java')],out/'compile-fixtures')
    results = []; failure = None
    for name, config in configs.items():
        if args.cell and args.cell != name: continue
        directory = out/name; directory.mkdir(exist_ok=True)
        config_file = save(directory/'config.json', config); http = None
        try:
            if name.endswith('-http'):
                http = OwnedProcess([node,str(installed/'@playwright/mcp/cli.js'),'--headless','--isolated','--host','127.0.0.1','--allowed-hosts',f'127.0.0.1:{port},localhost:{port}','--port',str(port)],directory/'http-server')
                wait_port(port)
            reference = RawClient(config,directory/'reference',manifest['protocolOffer'])
            try: original = reference.collect()
            finally: reference.close()
            save(directory/'reference-tools.json',original)
            expected = sorted([tool_fields(t) for t in original['tools']],key=lambda t:t['name'])
            assert expected and len({t['name'] for t in expected})==len(expected)
            snapshots = []
            for repeat in range(3):
                snapshot_path = directory/f'snapshot-{repeat}.json'
                run([*java,'snapshot','--config',str(config_file),'--out',str(snapshot_path)],directory/f'collect-{repeat}')
                snapshot = load(snapshot_path)
                assert sorted([tool_fields(t) for t in snapshot['tools']],key=lambda t:t['name'])==expected, 'wire evidence mismatch'
                snapshots.append(snapshot)
            assert len({s['surfaceFingerprint'] for s in snapshots})==1, 'unstable surface'
            run([java[0],'-cp',os.pathsep.join([str(classes),str(jar)]),'CollectionMetadata',str(config_file),str(directory/'collection-metadata.json')],directory/'collection-metadata')
            metadata=load(directory/'collection-metadata.json')
            assert metadata['protocolVersion'] and metadata['surfaceFingerprint']==snapshots[0]['surfaceFingerprint']
            run([java[0],'-cp',os.pathsep.join([str(classes),str(jar)]),'ValidationFixtures',str(directory),str(directory/'snapshot-0.json')], directory/'fixtures')
            reports = []
            for mode, source in [('online',['--config',str(config_file)]),('offline',['--snapshot',str(directory/'snapshot-0.json')]),('mutated',['--snapshot',str(directory/'changed.json')])]:
                report = directory/f'{mode}.report.json'; sarif = directory/f'{mode}.sarif'
                call = run([*java,'scan',*source,'--baseline',str(directory/'baseline.json'),'--json',str(report),'--sarif',str(sarif)],directory/mode,expected=(0,3,4))
                evidence = validate_report(report,sarif)
                assert evidence['checks']=={'staticRisk':'COMPLETE','drift':'COMPLETE'}
                reports.append((evidence,call))
            assert reports[0][0]['surfaceFingerprint']==reports[1][0]['surfaceFingerprint']
            assert reports[0][0]['findings']==reports[1][0]['findings']
            assert reports[0][1]['exitCode']==reports[1][1]['exitCode']
            assert reports[2][1]['exitCode'] in (3,4)
            assert reports[2][0]['surfaceFingerprint']!=snapshots[0]['surfaceFingerprint']
            assert reports[2][0]['diff']['blockingChanges']>0
            results.append({'cell':name,'status':'passed','tools':len(expected),'referenceProtocol':original['initialize']['protocolVersion'],
                            'sentinelProtocol':metadata['protocolVersion'],
                            'serverInfo':original['initialize']['serverInfo'],'surfaceFingerprint':snapshots[0]['surfaceFingerprint'],
                            'repeats':3,'onlineExit':reports[0][1]['exitCode'],'mutatedExit':reports[2][1]['exitCode'],
                            'outsideCoveredFields':sorted(set().union(*(set(t)-set(FIELDS) for t in original['tools'])))})
            print(f'{name}: PASS ({len(expected)} tools)', flush=True)
        except Exception as error:
            if hasattr(error, 'read'):
                (directory/'http-error.txt').write_bytes(error.read(65536))
            results.append({'cell':name,'status':'failed','errorType':type(error).__name__,'message':str(error)})
            failure = error
            print(f'{name}: FAIL ({type(error).__name__}): {error}', flush=True)
        finally:
            if http: http.finish(graceful=True)
            save(out/'summary.json',{'evidenceVersion':1,'platform':sys.platform,'machine':platform.platform(),
                 **source_identity(),
                 'nodeVersion':subprocess.check_output([node,'--version'],text=True).strip(),'pythonVersion':sys.version,
                 'jarSha256':sha(jar),'sbomSha256':sha(ROOT/'target/bom.json'),'manifestSha256':sha(ROOT/'validation/interop/manifest.json'),
                 'npmLockSha256':sha(ROOT/'validation/interop/package-lock.json'),'pythonLockSha256':sha(ROOT/'validation/interop/requirements-lock.txt'),
                 'cells':results,'stableRelease':'BLOCKED','provenance':'public-implementations-not-customer-pilots'})
    if failure: raise AssertionError('Interoperability cells failed; see summary.json') from failure
    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--jar',type=Path,default=ROOT/'target/mcp-sentinel.jar')
    parser.add_argument('--output',type=Path,default=ROOT/'target/interop'); parser.add_argument('--cell',choices=['filesystem-stdio','git-stdio','playwright-stdio','playwright-http'])
    verify(parser.parse_args())
