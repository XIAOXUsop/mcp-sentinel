#!/usr/bin/env python3
"""Package exactly the already-tested artifact; never rebuild it for publication."""
import argparse
import hashlib
import json
from pathlib import Path
from candidate_common import POLICY, identity, require, require_stable_allowed
from check_candidate_evidence import verify


def package(directory: Path, tag: str, commit: str, *, evidence_root: Path,
            expected_identity: dict, policy_path: Path = POLICY):
    require_stable_allowed(policy_path)
    candidate = verify(evidence_root, expected_identity, candidate=True, policy_path=policy_path)
    require(expected_identity['commit'] == commit, 'Release and candidate source differ')
    jar = directory / 'mcp-sentinel.jar'
    evidence_path = directory / 'artifact-verification/build-evidence.json'
    evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
    bom = json.loads((directory / 'bom.json').read_text(encoding='utf-8'))
    if evidence['jarSha256'] != hashlib.sha256(jar.read_bytes()).hexdigest():
        raise ValueError('JAR differs from the tested artifact')
    if evidence['sbomSha256'] != hashlib.sha256((directory / 'bom.json').read_bytes()).hexdigest():
        raise ValueError('SBOM differs from the tested artifact inventory')
    if evidence['commit'] != commit:
        raise ValueError('Artifact was tested on a different commit')
    require(candidate['artifact'] == {'jarSha256': evidence['jarSha256'], 'sbomSha256': evidence['sbomSha256']},
            'Release artifact differs from complete candidate acceptance')
    if tag != 'v' + evidence['toolVersion']:
        raise ValueError('Tag and tested tool version differ')
    if bom.get('bomFormat') != 'CycloneDX' or bom.get('metadata', {}).get('component', {}).get('version') != evidence['toolVersion']:
        raise ValueError('SBOM is missing or describes a different version')
    components = bom.get('components', [])
    if not components:
        raise ValueError('SBOM has no dependency components')
    inventory = '\n'.join(sorted(f"{c.get('group', '')}:{c['name']}:{c.get('version', '')}" for c in components)) + '\n'
    (directory / 'DEPENDENCIES.txt').write_text(inventory, encoding='utf-8')
    (directory / 'build-evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')
    names = ['mcp-sentinel.jar', 'bom.json', 'DEPENDENCIES.txt', 'build-evidence.json']
    checksums = '\n'.join(hashlib.sha256((directory / name).read_bytes()).hexdigest() + '  ' + name for name in names) + '\n'
    (directory / 'SHA256SUMS.txt').write_text(checksums, encoding='utf-8')
    return names + ['SHA256SUMS.txt']


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=Path('target'))
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--candidate-evidence', type=Path, required=True)
    args = parser.parse_args()
    print('\n'.join(package(args.directory, args.tag, args.commit,
                            evidence_root=args.candidate_evidence, expected_identity=identity())))
