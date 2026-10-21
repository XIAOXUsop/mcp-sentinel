"""Run the actual unittest suite and retain machine-readable, strict outcomes."""
import sys
import unittest
from candidate_common import ROOT, save

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'scripts'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    data = {'testsRun': result.testsRun, **{key: len(getattr(result, key)) for key in
            ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}}
    save(ROOT / 'target/python-tests.json', data)
    sys.exit(0 if data['testsRun'] > 0 and all(v == 0 for k, v in data.items() if k != 'testsRun') else 1)
