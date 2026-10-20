import json
from pathlib import Path
import tempfile
import unittest
import fetch_dependabot_alerts as fetcher
import release_preflight as gate

def alert(number, severity='low'):
    return {'number':number,'dependency':{'package':{'name':'synthetic'}},
            'security_advisory':{'severity':severity,'summary':'synthetic advisory','ghsa_id':'synthetic'}}

class Pagination(unittest.TestCase):
    def check(self, alerts, pages):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); output = base/'alerts.json'; receipt = base/'receipt.json'; http = base/'http'
            fetcher.write_inventory(alerts,pages,'owner/repo',output,receipt); http.write_text('200')
            return gate.check_alerts(http,output,'high',lambda *_: None,receipt_path=receipt)
    def test_second_page_high_blocks(self):
        pages = iter([[alert(i) for i in range(100)],[alert(100,'high')]])
        alerts, count = fetcher.collect('owner/repo',lambda url:next(pages))
        self.assertEqual(count,2); self.assertFalse(self.check(alerts,count))
    def test_full_last_page_requires_an_extra_empty_page(self):
        pages = iter([[alert(i) for i in range(100)],[]])
        alerts, count = fetcher.collect('owner/repo',lambda url:next(pages))
        self.assertEqual(count,2); self.assertTrue(self.check(alerts,count))
    def test_second_page_failure_is_not_partial_success(self):
        def request(url):
            if url.endswith('&page=1'): return [alert(i) for i in range(100)]
            raise TimeoutError('synthetic network failure')
        self.assertRaises(TimeoutError,fetcher.collect,'owner/repo',request)
    def test_repeated_page_is_rejected(self):
        self.assertRaises(ValueError,fetcher.collect,'owner/repo',lambda url:[alert(i) for i in range(100)])
    def test_wrong_body_and_missing_token_are_rejected(self):
        self.assertRaises(ValueError,fetcher.collect,'owner/repo',lambda url:{'message':'forbidden'})
        self.assertRaises(ValueError,fetcher.fetch,'owner/repo','')
    def test_receipt_does_not_authorize_changed_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); output = base/'alerts.json'; receipt = base/'receipt'; http = base/'http'
            fetcher.write_inventory([],1,'owner/repo',output,receipt); http.write_text('200'); output.write_text('[{}]')
            self.assertFalse(gate.check_alerts(http,output,'high',lambda *_: None,receipt_path=receipt))
