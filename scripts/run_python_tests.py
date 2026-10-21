"""Run the actual unittest suite and retain machine-readable, strict outcomes."""
import os
import sys
import unittest
from candidate_common import ROOT, save

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'scripts'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    data = {'testsRun': result.testsRun, **{key: len(getattr(result, key)) for key in
            ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}}
    save(ROOT / 'target/python-tests.json', data)
    # Publish only the test identity and final exception line in check annotations.
    # Full stdout/stderr stays in the usual logs and retained diagnostics.
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        for test, detail in [*result.failures, *result.errors]:
            message = f'{test.id()}: {detail.strip().splitlines()[-1]}'
            escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print(f'::error title=Python regression failed::{escaped}', flush=True)
    sys.exit(0 if data['testsRun'] > 0 and all(v == 0 for k, v in data.items() if k != 'testsRun') else 1)
