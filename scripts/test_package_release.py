import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from package_release import package


class PackageReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / 'artifact-verification').mkdir()
        (self.directory / 'mcp-sentinel.jar').write_bytes(b'tested-binary')
        evidence = {'toolVersion': '0.6.0', 'commit': 'abc', 'jarSha256': hashlib.sha256(b'tested-binary').hexdigest()}
        (self.directory / 'bom.json').write_text(json.dumps({'bomFormat': 'CycloneDX', 'metadata': {'component': {'version': '0.6.0'}},
                                                          'components': [{'group': 'test', 'name': 'dependency', 'version': '1'}]}))
        evidence['sbomSha256'] = hashlib.sha256((self.directory / 'bom.json').read_bytes()).hexdigest()
        (self.directory / 'artifact-verification/build-evidence.json').write_text(json.dumps(evidence))

    def test_exact_artifact_produces_verifiable_checksums(self):
        files = package(self.directory, 'v0.6.0', 'abc')
        self.assertIn('SHA256SUMS.txt', files)
        for line in (self.directory / 'SHA256SUMS.txt').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.directory / name).read_bytes()).hexdigest())

    def test_wrong_tag_or_commit_is_rejected(self):
        with self.assertRaises(ValueError): package(self.directory, 'v0.5.6', 'abc')
        with self.assertRaises(ValueError): package(self.directory, 'v0.6.0', 'different')

    def test_replaced_binary_is_rejected(self):
        (self.directory / 'mcp-sentinel.jar').write_bytes(b'untested')
        with self.assertRaises(ValueError): package(self.directory, 'v0.6.0', 'abc')

    def test_replaced_sbom_is_rejected(self):
        (self.directory / 'bom.json').write_text('{}')
        with self.assertRaises(ValueError): package(self.directory, 'v0.6.0', 'abc')
