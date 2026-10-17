"""Exercise validator exit codes and UTF-8 output under a Windows legacy encoding."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from check_sarif_schema import MINIMAL_SAMPLE


SCRIPT = Path(__file__).with_name('check_sarif_schema.py')


class ValidatorEncodingTest(unittest.TestCase):
    def invoke(self, *arguments):
        environment = dict(os.environ, PYTHONIOENCODING='cp1252')
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, arguments)], env=environment,
                              capture_output=True, timeout=30)

    def test_selftest_succeeds_with_cp1252_environment(self):
        result = self.invoke('--selftest')
        self.assertEqual(0, result.returncode, result.stderr.decode('utf-8', errors='replace'))
        self.assertIn('自检通过', result.stdout.decode('utf-8'))
        self.assertIn('logicalLocations', result.stderr.decode('utf-8'))
        self.assertIn('tags 写成字符串', result.stderr.decode('utf-8'))

    def test_valid_report_keeps_non_ascii_path_and_success_status(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / '中文报告.sarif'
            path.write_text(json.dumps(MINIMAL_SAMPLE, ensure_ascii=False), encoding='utf-8')
            result = self.invoke(path)
            self.assertEqual(0, result.returncode, result.stderr.decode('utf-8', errors='replace'))
            self.assertIn(path.name, result.stdout.decode('utf-8'))
            self.assertIn('0 个 schema 错误', result.stdout.decode('utf-8'))

    def test_invalid_report_keeps_diagnostic_and_failure_status(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / '错误报告.sarif'
            report = copy.deepcopy(MINIMAL_SAMPLE)
            report['version'] = 'invalid'
            path.write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')
            result = self.invoke(path)
            self.assertEqual(1, result.returncode)
            error = result.stderr.decode('utf-8')
            self.assertIn(path.name, error)
            self.assertIn('/version', error)
            self.assertNotIn('Traceback', error)


if __name__ == '__main__':
    unittest.main()
