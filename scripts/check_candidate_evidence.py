#!/usr/bin/env python3
"""Validate source-bound raw candidate evidence, not just a green summary."""
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

from candidate_common import (ROOT, check_files, child, identity, load, now, policy,
                              read_indexed, require, save, sha, source_inputs)

CELLS = {'filesystem-stdio', 'git-stdio', 'playwright-stdio', 'playwright-http'}
SCENARIOS = {f'offline-{n}-{noise}' for n in (100, 1000) for noise in ('False', 'True')} | {
    'stdio-100', 'stdio-1000', 'http-100', 'http-1000', 'external-filesystem', 'external-playwright-http'}
APPROVALS = {'interrupt-before', 'interrupt-after', 'independent-cli-approval-race', 'trusted-comparison',
             'candidate-self-baseline', 'stale-approval-preserves-baseline', 'output-failure-preserves-baseline'}
STAGES = {'build', 'artifact', 'evaluation', 'python', 'schema', 'secret', 'interop',
          'approval', 'demo', 'corpus', 'performance'}
EVIDENCE_DIRS = ('artifact-verification', 'evaluation', 'surefire-reports', 'interop',
                 'approval-processes', 'candidate-demo', 'manual-corpus', 'performance')


def platform_checks(root, files, expected, platform):
    """Inspect required raw outcomes after verifying every indexed file digest."""
    read = lambda name: read_indexed(root, files, name)
    build = read('artifact-verification/build-evidence.json')
    require(build['commit'] == expected['commit'] and build['platform'] == platform, 'Build evidence source/platform mismatch')
    require(build['jarSha256'] == files['mcp-sentinel.jar'] and build['sbomSha256'] == files['bom.json'],
            'Build artifact digest mismatch')
    require(build['reportVersion'] == 3 and build['cliChecks'] >= 33 and
            len(build['calls']) == build['cliChecks'] and
            all(c['exitCode'] == c['expectedExit'] for c in build['calls']), 'Actual JAR checks incomplete')
    require(build['jsonReportsValidated'] >= 24 and build['sarifFilesValidated'] >= 24 and
            build['jsonSchemaNegativeChecks'] >= 3 and build['trustRegressionChecks'] >= 4,
            'Report/trust checks incomplete')
    xml_files = [n for n in files if n.startswith('surefire-reports/TEST-') and n.endswith('.xml')]
    require(xml_files, 'Java test records missing')
    tests = 0
    for name in xml_files:
        suite = ET.parse(child(root, name)).getroot()
        tests += int(suite.attrib['tests'])
        require(all(int(suite.attrib.get(k, 0)) == 0 for k in ('errors', 'failures', 'skipped')), 'Java tests failed/skipped')
    require(tests > 0, 'No Java tests ran')
    python = read('python-tests.json')
    require(python['testsRun'] > 0 and all(python[k] == 0 for k in
            ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')), 'Python tests failed/skipped')
    evaluation = read('evaluation/summary.json')
    require(evaluation['comparisons'] == 300 and evaluation['independentWitnessChecks'] == 600 and
            evaluation['riskProbes'] == 200 and evaluation['failedExpectations'] == 0, 'Generated evaluation incomplete')
    interop = read('interop/summary.json')
    require(interop['commit'] == expected['commit'] and interop['platform'] == platform, 'Interop source/platform mismatch')
    for doc in (interop, read('performance/summary.json')):
        require(doc['jarSha256'] == build['jarSha256'] and doc['sbomSha256'] == build['sbomSha256'],
                'Engineering tests used different artifact bytes')
        require(doc['commit'] == expected['commit'] and doc['workingTreeDirty'] is False, 'Engineering source mismatch')
    cells = interop['cells']
    require(len(cells) == 4 and {c['cell'] for c in cells} == CELLS, 'Interop cell set incomplete')
    for cell in cells:
        require(cell['status'] == 'passed' and cell['repeats'] == 3 and cell['tools'] > 0 and
                cell['referenceProtocol'] and cell['sentinelProtocol'], 'Interop cell not passed')
        for suffix in ('online.report.json', 'offline.report.json', 'mutated.report.json',
                       'reference-tools.json', 'collection-metadata.json'):
            read(f"interop/{cell['cell']}/{suffix}")
        changed = read(f"interop/{cell['cell']}/mutated.report.json")
        require(changed['diff']['blockingChanges'] > 0 and changed['exitCode'] in (3, 4), 'Drift probe failed')
    approval = read('approval-processes/summary.json')
    require(approval['jarSha256'] == build['jarSha256'] and approval['platform'] == platform, 'Approval artifact mismatch')
    require(len(approval['checks']) == 7 and {c['case'] for c in approval['checks']} == APPROVALS and
            all(c['status'] == 'passed' for c in approval['checks']), 'Approval checks incomplete')
    race = next(c for c in approval['checks'] if c['case'] == 'independent-cli-approval-race')
    require(sorted(race['exitCodes']) == [0, 5], 'Concurrent approval did not reject a stale writer')
    demo = read('candidate-demo/summary.json')
    require(demo['jarSha256'] == build['jarSha256'] and
            [s['exitCode'] for s in demo['steps']] == [0, 4, 0, 0, 5], 'Candidate demo incomplete')
    corpus = read('manual-corpus/samples.json')
    require(corpus['humanLabels'] == 0 and corpus['holdoutSamples'] == 0 and len(corpus['samples']) == 20,
            'Automatic corpus must remain unlabeled development data')
    performance = read('performance/summary.json')
    require(performance['warmups'] == 3 and performance['repetitions'] == 20, 'Resource measurements incomplete')
    scenarios = performance['scenarios']
    require(len(scenarios) == 10 and {s['scenario'] for s in scenarios} == SCENARIOS, 'Resource scenario set incomplete')
    require(performance['measurementContextSha256'] == files['performance/measurement-context.json'],
            'Measurement context mismatch')
    context = read('performance/measurement-context.json')
    require(context['commit'] == expected['commit'] and context['jarSha256'] == build['jarSha256'],
            'Measurement context source mismatch')
    for case in scenarios:
        name = f"performance/{case['scenario']}/samples.json"
        samples = read(name)
        require(case['samplesSha256'] == files[name] and case['measured'] == 20 and len(samples) == 23,
                'Measurement sample count/hash mismatch')
        expected_exit = 3 if case['scenario'].endswith('-True') else 0
        for index, sample in enumerate(samples):
            require(sample['warmup'] is (index < 3) and sample['exitCode'] == sample['expectedExit'] == expected_exit and
                    sample['rootPeakRssBytes'] > 0 and sample['elapsedSeconds'] > 0, 'Measurement failed')
    continuous = read('performance/continuous.json')
    require(continuous == {'runs': 30, 'toolFailures': 0, 'ownedProcessLeaks': 0}, 'Continuous scans incomplete')
    for index in range(30):
        require(read(f'performance/continuous/{index}/call.json')['exitCode'] == 0, 'Continuous scan failed')
    bounds = read('performance/boundaries/summary.json')
    require(bounds['status'] == 'passed' and [c['exitCode'] for c in bounds['checks']] == [2, 1, 2, 2],
            'Boundary checks incomplete')
    require(all(c['elapsedSeconds'] < 8 and c.get('verifiedEndedPids')
                for c in bounds['checks'][2:]), 'Boundary cleanup evidence missing')
    processes = [n for n in files if n.endswith('/process.json')]
    require(processes, 'No process cleanup evidence')
    for name in processes:
        require(read(name)['remainingBeforeEmergencyCleanup'] == [], 'Owned process remained alive')
    return {'javaTests': tests, 'pythonTests': python['testsRun'], 'cliChecks': build['cliChecks'],
            'interopCells': 4, 'resourceScenarios': 10, 'approvalChecks': 7}


def record_platform(root, platform, stages, expected):
    require(set(stages) == STAGES and all(v == 'success' for v in stages.values()), 'Required stage failed/skipped')
    paths = [root / 'mcp-sentinel.jar', root / 'bom.json', root / 'python-tests.json']
    for directory in EVIDENCE_DIRS:
        # Actions excludes hidden files by default. Temporary Git internals are
        # test setup, not retained evidence; do not index unuploaded .git files.
        paths.extend(p for p in (root / directory).rglob('*')
                     if p.is_file() and not any(part.startswith('.') for part in p.relative_to(root).parts))
    files = {p.relative_to(root).as_posix(): sha(p) for p in sorted(set(paths))}
    coverage = platform_checks(root, files, expected, platform)
    receipt = {'evidenceVersion': 1, 'kind': 'platform', 'identity': expected, 'platform': platform,
               'createdAtUtc': now(), 'sourceInputs': source_inputs(), 'stages': stages,
               'coverage': coverage, 'files': files}
    save(root / 'platform-receipt.json', receipt)
    return receipt


def verify_platform(root, expected, platform, inputs):
    receipt = load(root / 'platform-receipt.json')
    require(receipt['evidenceVersion'] == 1 and receipt['kind'] == 'platform' and
            receipt['identity'] == expected and receipt['platform'] == platform, 'Platform receipt identity mismatch')
    require(receipt['sourceInputs'] == inputs, 'Validation source inputs differ')
    require(set(receipt['stages']) == STAGES and all(v == 'success' for v in receipt['stages'].values()),
            'Required stage failed/skipped')
    check_files(root, receipt['files'])
    require(receipt['coverage'] == platform_checks(root, receipt['files'], expected, platform), 'Coverage summary mismatch')
    return receipt


def verify(root, expected, *, candidate=False, policy_path=None):
    inputs = source_inputs()
    receipts = {platform: verify_platform(root / platform, expected, platform, inputs) for platform in ('linux', 'win32')}
    linux = receipts['linux']['files']
    require(all(receipts['win32']['files'][n] == linux[n] for n in ('mcp-sentinel.jar', 'bom.json')),
            'Platforms tested different JAR/SBOM bytes')
    sarif = load(root / 'sarif/receipt.json')
    require(sarif['identity'] == expected and sarif['jarSha256'] == linux['mcp-sentinel.jar'] and
            sarif['scanOutcome'] == 'failure' and sarif['uploadOutcome'] == 'success',
            'Actual SARIF ingestion has not succeeded for this candidate')
    check_files(root / 'sarif', sarif['files'])
    report = read_indexed(root / 'sarif', sarif['files'], 'report.json')
    require(report['exitCode'] == 4 and report['diff']['blockingChanges'] == 1 and report['findings'] == [],
            'SARIF scan did not have the expected independent failure')
    decision = policy(policy_path) if policy_path else policy()
    require(decision['repository'] == expected['repository'], 'Policy repository mismatch')
    result = {'evidenceVersion': 1, 'identity': expected, 'sourceInputs': inputs, 'engineeringStatus': 'PASSED',
              'candidateStatus': 'NOT_YET_CONSUMED', 'stableReleaseStatus': 'BLOCKED',
              'stablePublicationAllowed': decision['stablePublicationAllowed'],
              'dependencyInventory': 'NOT_VERIFIED_BY_CANDIDATE_TESTS',
              'humanAcceptance': decision['humanAcceptance'],
              'artifact': {'jarSha256': linux['mcp-sentinel.jar'], 'sbomSha256': linux['bom.json']},
              'platformReceipts': {p: sha(root / p / 'platform-receipt.json') for p in receipts},
              'sarifReceiptSha256': sha(root / 'sarif/receipt.json')}
    if candidate:
        archives = list((root / 'bundle').glob('*.zip'))
        require(len(archives) == 1, 'Expected exactly one candidate archive')
        digest = sha(archives[0])
        for platform in ('linux', 'win32'):
            consumed = load(root / 'consumption' / f'{platform}.json')
            require(consumed['identity'] == expected and consumed['platform'] == platform and
                    consumed['archiveSha256'] == digest and consumed['jarSha256'] == linux['mcp-sentinel.jar'] and
                    consumed['status'] == 'passed' and consumed['exitCodes'] == [0, 4, 0, 0, 5] and
                    consumed['developmentToolsOnPath'] == [] and consumed['staleApprovalExit'] == 5 and
                    consumed['missingJavaExit'] != 0, 'Independent package consumption incomplete')
            check_files(root / 'consumption', consumed['files'])
        result.update(candidateStatus='READY_FOR_HANDOFF', archive=archives[0].name, archiveSha256=digest)
    from jsonschema import Draft202012Validator
    Draft202012Validator(load(ROOT / 'schemas/candidate-evidence-v1.schema.json')).validate(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['platform', 'engineering', 'candidate', 'adopt'])
    parser.add_argument('--root', type=Path, default=ROOT / 'target')
    parser.add_argument('--platform', choices=['linux', 'win32'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    expected = identity()
    if args.mode == 'platform':
        import os
        record_platform(args.root, args.platform, json.loads(os.environ['STAGE_OUTCOMES']), expected)
    elif args.mode == 'adopt':
        import shutil
        verify_platform(args.root, expected, 'linux', source_inputs())
        for name in ('mcp-sentinel.jar', 'bom.json'):
            shutil.copyfile(args.root / name, ROOT / 'target' / name)
        save(ROOT / 'target/canonical-source.json', {'identity': expected, 'receiptSha256': sha(args.root / 'platform-receipt.json')})
    else:
        result = verify(args.root, expected, candidate=args.mode == 'candidate')
        save(args.output or args.root / (args.mode + '.json'), result)
        print(f"{args.mode}: {result['candidateStatus']}; stable release: BLOCKED")
        if args.mode == 'candidate':
            import os
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                # Public check metadata contains only candidate identities/digests,
                # never raw declarations, environment values or test logs.
                summary = {key: result[key] for key in ('identity', 'candidateStatus', 'stableReleaseStatus',
                                                        'artifact', 'archive', 'archiveSha256')}
                summary['coverage'] = {platform: load(args.root / platform / 'platform-receipt.json')['coverage']
                                       for platform in ('linux', 'win32')}
                message = json.dumps(summary, ensure_ascii=True).replace('%', '%25')
                print(f'::notice title=Candidate acceptance receipt::{message}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'Candidate evidence rejected: {error}', file=sys.stderr)
        sys.exit(1)
