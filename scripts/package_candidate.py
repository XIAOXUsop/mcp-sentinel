#!/usr/bin/env python3
"""Assemble immutable offline input bytes and the validated JAR, without a build."""
import argparse
from pathlib import Path
import shutil
import tempfile
import zipfile

from candidate_common import ROOT, identity, load, require, save, sha
from check_candidate_evidence import verify


def assemble(root, expected):
    engineering = verify(root, expected)
    source = root / 'linux'
    version = load(source / 'artifact-verification/build-evidence.json')['toolVersion']
    name = f"mcp-sentinel-candidate-{version}-{expected['commit'][:12]}"
    require(all(c.isalnum() or c in '.-_' for c in name), 'Unsafe archive name')
    output = root / 'bundle'
    output.mkdir(exist_ok=True)
    require(not list(output.glob('*.zip')), 'Do not replace an existing candidate archive')
    with tempfile.TemporaryDirectory(prefix='sentinel-package-') as temporary:
        package = Path(temporary) / name
        package.mkdir()
        for file in ('mcp-sentinel.jar', 'bom.json'):
            shutil.copyfile(source / file, package / file)
        shutil.copyfile(ROOT / 'LICENSE', package / 'LICENSE')
        with zipfile.ZipFile(package / 'mcp-sentinel.jar') as jar:
            # Preserve notices from the exact already-tested shaded JAR.
            for entry in ('META-INF/LICENSE', 'META-INF/NOTICE'):
                if entry in jar.namelist():
                    (package / ('THIRD-PARTY-' + entry.split('/')[-1] + '.txt')).write_bytes(jar.read(entry))
        components = load(package / 'bom.json')['components']
        (package / 'DEPENDENCIES.txt').write_text(
            '\n'.join(sorted(f"{c.get('group','')}:{c['name']}:{c.get('version','')}" for c in components)) + '\n',
            encoding='utf-8', newline='\n')
        # The demo baseline in inputs/ was mutated by approval. Use the immutable seed baseline.
        mappings = {
            'candidate-demo/seed/synthetic-100-false.snapshot.json': 'before.json',
            'candidate-demo/seed/synthetic-100-false.baseline.json': 'baseline.json',
            'candidate-demo/inputs/changed.json': 'changed.json',
        }
        (package / 'examples').mkdir()
        for original, filename in mappings.items():
            shutil.copyfile(source / original, package / 'examples' / filename)
        for file in (ROOT / 'validation/candidate-kit').iterdir():
            require(file.is_file(), 'Unexpected kit template directory')
            shutil.copyfile(file, package / file.name)
        save(package / 'candidate-manifest.json', {
            'manifestVersion': 1, 'identity': expected, 'toolVersion': version,
            'jarSha256': engineering['artifact']['jarSha256'], 'sbomSha256': engineering['artifact']['sbomSha256'],
            'assemblyStatus': 'ENGINEERING_VERIFIED_CONSUMPTION_PENDING',
            'stableRelease': 'BLOCKED', 'inputKind': 'synthetic offline data',
            'humanAcceptance': engineering['humanAcceptance'],
        })
        checksums = ''.join(f'{sha(p)}  {p.relative_to(package).as_posix()}\n'
                            for p in sorted(package.rglob('*')) if p.is_file())
        (package / 'SHA256SUMS.txt').write_text(checksums, encoding='utf-8', newline='\n')
        archive = output / (name + '.zip')
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as zipped:
            for file in sorted(package.rglob('*')):
                if file.is_file():
                    zipped.write(file, name + '/' + file.relative_to(package).as_posix())
    (output / (archive.name + '.sha256')).write_text(sha(archive) + '  ' + archive.name + '\n', encoding='utf-8')
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    print(assemble(args.evidence, identity()))
