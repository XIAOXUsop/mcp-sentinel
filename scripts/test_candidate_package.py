"""Exercise the real JAR and kit scripts in a disposable Java-only consumer."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from candidate_common import ROOT, policy, save, sha
from package_candidate import assemble
from verify_candidate_package import consume
from test_candidate_evidence import IDENTITY


class CandidatePackage(unittest.TestCase):
    def test_real_jar_package_is_consumable_without_development_tools(self):
        # Synthetic gate context tests the packager, not actual engineering
        # acceptance. Real candidate workflows never mock the evidence gate.
        jar=ROOT/'target/mcp-sentinel.jar'
        self.assertTrue(jar.is_file(), 'Build the actual JAR before this integration test')
        java=Path(os.environ['JAVA_HOME'])/'bin'/('java.exe' if os.name=='nt' else 'java')
        with tempfile.TemporaryDirectory(prefix='kit-integration-') as temporary:
            root=Path(temporary); source=root/'linux'; source.mkdir()
            for name in ('mcp-sentinel.jar','bom.json'):
                shutil.copyfile(ROOT/'target'/name,source/name)
            seed=source/'candidate-demo/seed'; inputs=source/'candidate-demo/inputs'
            for args in ([str(seed)],[str(inputs),str(seed/'synthetic-100-false.snapshot.json')]):
                subprocess.run([str(java),'--class-path',str(jar),str(ROOT/'scripts/ValidationFixtures.java'),*args],
                               check=True,capture_output=True,timeout=60)
            version=subprocess.check_output([str(java),'-jar',str(jar),'--version'],text=True).strip().removeprefix('mcp-sentinel ')
            save(source/'artifact-verification/build-evidence.json',{'toolVersion':version})
            accepted={'artifact':{'jarSha256':sha(jar),'sbomSha256':sha(source/'bom.json')},
                      'humanAcceptance':policy()['humanAcceptance']}
            with patch('package_candidate.verify',return_value=accepted):
                archive=assemble(root,IDENTITY)
            with zipfile.ZipFile(archive) as zipped:
                self.assertFalse(any('manual-corpus' in n or 'reference-tools' in n for n in zipped.namelist()))
            result=consume(root/'bundle',root/'consumer',IDENTITY)
            self.assertEqual(result['exitCodes'],[0,4,0,0,5])
            self.assertEqual(result['developmentToolsOnPath'],[])
            self.assertEqual(result['jarSha256'],sha(jar))
            with patch('package_candidate.verify',return_value=accepted), self.assertRaises(ValueError):
                assemble(root,IDENTITY)
