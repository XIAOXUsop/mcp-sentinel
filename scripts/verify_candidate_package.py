#!/usr/bin/env python3
"""Consume the ZIP outside the repository using a Java runtime without development tools."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

from candidate_common import child, identity, load, require, save, sha


def consume(bundle, output, expected):
    archives = list(bundle.glob('*.zip'))
    require(len(archives) == 1, 'Expected one candidate ZIP')
    archive = archives[0]
    require((bundle / (archive.name + '.sha256')).read_text().split()[0] == sha(archive), 'ZIP digest mismatch')
    platform = sys.platform
    records = output / platform
    records.mkdir(parents=True, exist_ok=True)
    shell = shutil.which('pwsh') if os.name == 'nt' else '/bin/sh'
    require(shell, 'PowerShell 7 is needed by the Windows verification harness')
    java_home = Path(os.environ['JAVA_HOME'])
    jlink = java_home / 'bin' / ('jlink.exe' if os.name == 'nt' else 'jlink')
    with tempfile.TemporaryDirectory(prefix='sentinel consumer 中文 ') as temporary:
        work = Path(temporary)
        runtime = work / 'runtime'
        # Development tools belong only to the harness. The child environment has a runtime-only PATH.
        subprocess.run([str(jlink), '--add-modules', 'java.se,jdk.unsupported,jdk.crypto.ec',
                        '--strip-debug', '--no-header-files', '--no-man-pages', '--output', str(runtime)],
                       check=True, capture_output=True, timeout=180)
        with zipfile.ZipFile(archive) as zipped:
            for name in zipped.namelist():
                child(work, name)
            zipped.extractall(work)
        candidates = [p for p in work.iterdir() if p.is_dir() and p.name.startswith('mcp-sentinel-candidate-')]
        require(len(candidates) == 1, 'Ambiguous package root')
        package = candidates[0]
        manifest = load(package / 'candidate-manifest.json')
        require(manifest['identity'] == expected and manifest['jarSha256'] == sha(package / 'mcp-sentinel.jar'),
                'Package source/JAR mismatch')
        for line in (package / 'SHA256SUMS.txt').read_text().splitlines():
            digest, name = line.split('  ', 1)
            require(sha(child(package, name)) == digest, 'Package content digest mismatch')
        environment = dict(os.environ, PATH=str(runtime / 'bin'), JAVA_HOME=str(runtime),
                           PYTHONPATH='', CLASSPATH='', BASH_ENV='', ENV='')
        for variable in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'):
            environment.pop(variable, None)
        # On Windows shutil.which may also search the harness's current source
        # directory (where mvnw exists). Inspect the child PATH and child cwd.
        extensions = ('', '.exe', '.cmd', '.bat') if os.name == 'nt' else ('',)
        tools = [name for name in ('javac', 'mvn', 'mvnw', 'python', 'python3', 'node', 'npm')
                 if any((directory / (name + suffix)).is_file()
                        for directory in (runtime / 'bin', package) for suffix in extensions)]
        require(not tools, 'Development tools are visible to the consumer')
        calls = []

        def step(name, expected_exit, *fingerprints, env=None):
            launcher = ([shell, '-NoProfile', '-NonInteractive', '-File', str(package / 'demo.ps1')]
                        if os.name == 'nt' else [shell, str(package / 'demo.sh')])
            start = time.monotonic()
            result = subprocess.run([*launcher, name, *fingerprints], cwd=package,
                                    env=env or environment, capture_output=True, timeout=60)
            label = f'{len(calls):02}-{name}'
            (records / (label + '.stdout')).write_bytes(result.stdout)
            (records / (label + '.stderr')).write_bytes(result.stderr)
            calls.append({'step': name, 'exitCode': result.returncode, 'expectedExit': expected_exit,
                          'elapsedSeconds': time.monotonic() - start})
            require(result.returncode == expected_exit,
                    f'Package step {name}: expected {expected_exit}, got {result.returncode}; stderr={result.stderr[-1200:]!r}')
            return result.returncode

        codes = [step('init', 0), step('review', 4)]
        review = load(package / 'work/02-drift.json')
        baseline_digest = sha(package / 'work/baseline.json')
        stale = step('approve', 5, '0' * 64, review['surfaceFingerprint'])
        require(sha(package / 'work/baseline.json') == baseline_digest, 'Stale approval changed baseline')
        codes += [step('approve', 0, review['baselineFingerprint'], review['surfaceFingerprint']),
                  step('rescan', 0), step('missing', 5)]
        failed = load(package / 'work/05-missing.json')
        require(failed['checks'] == {'staticRisk': 'NOT_RUN', 'drift': 'NOT_RUN'}, 'Missing baseline misrepresented')
        missing = dict(environment, PATH=str(work / 'no-java'), JAVA_HOME='')
        missing_exit = step('review', 1, env=missing)
        for file in (package / 'work').glob('*.json'):
            shutil.copyfile(file, records / file.name)
        save(records / 'calls.json', calls)
        files = {p.relative_to(output).as_posix(): sha(p) for p in records.iterdir() if p.is_file()}
        result = {'identity': expected, 'platform': platform, 'status': 'passed', 'exitCodes': codes,
                  'archiveSha256': sha(archive), 'jarSha256': manifest['jarSha256'],
                  'developmentToolsOnPath': tools, 'staleApprovalExit': stale,
                  'missingJavaExit': missing_exit, 'files': files,
                  'humanReplay': 'NOT_PERFORMED_AUTOMATED_CONSUMPTION_ONLY'}
        save(output / (platform + '.json'), result)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    consume(args.bundle.resolve(), args.output.resolve(), identity())
    print('Offline candidate consumed successfully with a Java-only PATH.')
