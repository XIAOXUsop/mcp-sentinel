"""Synthetic JSON transport fixture. It never executes tool calls."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys


def result(message, spec):
    method=message.get('method')
    if method=='initialize':
        value={'protocolVersion':message['params']['protocolVersion'],'capabilities':{'tools':{}},'serverInfo':{'name':spec['serverName'],'version':'1'}}
    elif method=='tools/list': value={'tools':spec['tools']}
    elif method.startswith('notifications/'): return None
    elif method=='ping': value={}
    else: return {'jsonrpc':'2.0','id':message.get('id'),'error':{'code':-32601,'message':'Unsupported method'}}
    return {'jsonrpc':'2.0','id':message['id'],'result':value}


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--spec',required=True); parser.add_argument('--port',type=int)
    args=parser.parse_args()
    with open(args.spec,encoding='utf-8') as stream: spec=json.load(stream)
    if not args.port:
        for line in sys.stdin:
            response=result(json.loads(line),spec)
            if response is not None: print(json.dumps(response),flush=True)
    else:
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args): pass
            def do_POST(self):
                size=int(self.headers.get('Content-Length','0'))
                if size>1024*1024: self.send_error(413); return
                response=result(json.loads(self.rfile.read(size)),spec)
                data=json.dumps(response).encode() if response else b''
                self.send_response(200 if response else 202)
                self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data)))
                self.end_headers(); self.wfile.write(data)
            def do_DELETE(self):
                self.send_response(204); self.send_header('Content-Length','0'); self.end_headers()
        ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
