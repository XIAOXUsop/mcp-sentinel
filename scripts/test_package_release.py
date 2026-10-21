import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
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
        self.policy = self.directory / 'policy.json'
        self.policy.write_text(json.dumps({'policyVersion':1,'repository':'XIAOXUsop/mcp-sentinel',
                                          'stablePublicationAllowed':True}))
        self.candidate = {'artifact': {k:evidence[k] for k in ('jarSha256','sbomSha256')}}

    def package(self, tag='v0.6.0', commit='abc'):
        # Candidate raw evidence validation has its own fault-injection suite.
        with patch('package_release.verify', return_value=self.candidate):
            return package(self.directory, tag, commit, evidence_root=self.directory,
                           expected_identity={'commit':'abc'}, policy_path=self.policy)

    def test_exact_artifact_produces_verifiable_checksums(self):
        files = self.package()
        self.assertIn('SHA256SUMS.txt', files)
        for line in (self.directory / 'SHA256SUMS.txt').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.directory / name).read_bytes()).hexdigest())

    def test_wrong_tag_or_commit_is_rejected(self):
        with self.assertRaises(ValueError): self.package('v0.5.6')
        with self.assertRaises(ValueError): self.package(commit='different')

    def test_replaced_binary_is_rejected(self):
        (self.directory / 'mcp-sentinel.jar').write_bytes(b'untested')
        with self.assertRaises(ValueError): self.package()

    def test_replaced_sbom_is_rejected(self):
        (self.directory / 'bom.json').write_text('{}')
        with self.assertRaises(ValueError): self.package()

    def test_green_candidate_cannot_lift_recorded_block(self):
        data=json.loads(self.policy.read_text()); data['stablePublicationAllowed']=False
        self.policy.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'blocked'): self.package()

    def test_release_bytes_must_match_full_candidate(self):
        self.candidate['artifact']['jarSha256']='0'*64
        with self.assertRaisesRegex(ValueError, 'complete candidate'): self.package()
