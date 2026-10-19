"""Local review fixture: preserves tools/list payload without SDK coercion."""
import json
from pathlib import Path
import sys

spec = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
for line in sys.stdin:
    req = json.loads(line)
    if 'id' not in req:
        continue
    if req.get('method') == 'initialize':
        result = {'protocolVersion': req['params']['protocolVersion'], 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'review-server', 'version': '1.0'}}
    elif req.get('method') == 'tools/list':
        result = spec
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': result}), flush=True)
