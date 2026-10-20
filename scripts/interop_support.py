"""Independent JSON-RPC client and owned-process evidence for validation only."""
from __future__ import annotations
import contextlib
import atexit
import hashlib
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

import psutil

ROOT = Path(__file__).resolve().parent.parent
FIELDS = ('name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations')
_OWNED = set()


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return path


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity():
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
    return {'commit':os.environ.get('GITHUB_SHA') or ('local-working-tree' if dirty else head),
            'sourceHead':head,'workingTreeDirty':dirty}


def java_command(jar):
    java = Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if os.name == 'nt' else 'java') if os.environ.get('JAVA_HOME') else 'java'
    return [str(java), '-jar', str(Path(jar).resolve())]


class OwnedProcess:
    def __init__(self, command, directory, *, pipes=False, env=None):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.stderr = (self.directory / 'stderr.txt').open('wb')
        self.stdout = None if pipes else (self.directory / 'stdout.txt').open('wb')
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE if pipes else subprocess.DEVNULL,
                                        stdout=subprocess.PIPE if pipes else self.stdout, stderr=self.stderr,
                                        cwd=ROOT, env=env)
        self.tracked = {self.process.pid: psutil.Process(self.process.pid)}
        _OWNED.add(self)
        self.stop = threading.Event()
        self.watcher = threading.Thread(target=self.watch, daemon=True); self.watcher.start()

    def watch(self):
        while not self.stop.wait(.02):
            try:
                for child in self.tracked[self.process.pid].children(recursive=True):
                    self.tracked[child.pid] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def alive(self):
        remaining=[]
        for process in list(self.tracked.values()):
            # A signaled Popen handle proves this process ended; Windows process
            # enumeration can briefly retain its PID while handles are closing.
            if process.pid==self.process.pid and self.process.poll() is not None: continue
            if not process.is_running(): continue
            try: process.wait(timeout=.05)
            except psutil.TimeoutExpired: remaining.append(process)
            except psutil.NoSuchProcess: pass
        return remaining

    def cleanup(self):
        # Children first, while their parent can still reap them.
        for p in reversed(list(self.tracked.values())):
            if p.pid == self.process.pid:
                if self.process.poll() is None:
                    self.process.terminate()
                    try: self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=2)
                continue
            with contextlib.suppress(psutil.Error): p.terminate()
            with contextlib.suppress(psutil.Error): p.wait(timeout=1)
            with contextlib.suppress(psutil.Error):
                if p.is_running(): p.kill(); p.wait(timeout=2)

    def finish(self, *, graceful=False):
        if graceful and self.process.poll() is None:
            if self.process.stdin:
                with contextlib.suppress(OSError): self.process.stdin.close()
            with contextlib.suppress(subprocess.TimeoutExpired): self.process.wait(timeout=3)
        # The reference client owns its server and explicitly ends it.
        if graceful and self.process.poll() is None: self.cleanup()
        self.stop.set(); self.watcher.join(timeout=1)
        remaining = [p.pid for p in self.alive()]
        save(self.directory / 'process.json', {'pid': self.process.pid, 'trackedPids': list(self.tracked),
                                             'remainingBeforeEmergencyCleanup': remaining,
                                             'exitCode': self.process.poll()})
        if remaining: self.cleanup()
        if self.stdout: self.stdout.close()
        self.stderr.close()
        if self.process.stdout:
            with contextlib.suppress(OSError): self.process.stdout.close()
        _OWNED.discard(self)
        if remaining: raise AssertionError(f'owned process remained alive: {remaining}')


def run(command, directory, expected=(0,), timeout=120):
    owned = OwnedProcess(command, directory); start = time.perf_counter()
    try:
        code = owned.process.wait(timeout=timeout)
    except BaseException:
        owned.cleanup(); owned.finish(); raise
    owned.finish()
    result = {'command': list(map(str, command)), 'exitCode': code, 'elapsedSeconds': time.perf_counter()-start}
    save(Path(directory) / 'call.json', result)
    if code not in expected:
        raise AssertionError(f'{command[0]} exited {code}: see {directory}')
    return result


class RawClient:
    """No Sentinel or typed MCP SDK objects participate in the reference result."""
    def __init__(self, config, directory, protocol='2025-11-25'):
        self.config = config; self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.protocol = protocol; self.session = None; self.counter = 0; self.transcript = []
        self.owned = None
        if config.get('transport', 'stdio') == 'stdio':
            self.owned = OwnedProcess([config['command'], *config.get('args', [])], self.directory, pipes=True)
            self.messages = queue.Queue()
            self.reader = threading.Thread(target=self.read, daemon=True); self.reader.start()

    def read(self):
        try:
            while line := self.owned.process.stdout.readline(16*1024*1024+1):
                if len(line) > 16*1024*1024: raise ValueError('reference line too large')
                self.messages.put(json.loads(line))
        except Exception as error: self.messages.put(error)
        finally: self.messages.put(EOFError('reference stdout closed'))

    def send(self, message):
        self.transcript.append({'direction': 'request', 'message': message})
        if self.owned:
            self.owned.process.stdin.write((json.dumps(message)+'\n').encode()); self.owned.process.stdin.flush()
            return
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                   'MCP-Protocol-Version': self.protocol}
        if self.session: headers['Mcp-Session-Id'] = self.session
        request = urllib.request.Request(self.config['url'], json.dumps(message).encode(), headers=headers)
        # Test endpoints are loopback; never inherit a machine proxy for them.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as response:
            if response.headers.get('Mcp-Session-Id'): self.session = response.headers['Mcp-Session-Id']
            if response.status == 202: return
            if 'text/event-stream' in response.headers.get('Content-Type', ''):
                data = []; consumed = 0
                while line := response.readline(2*1024*1024):
                    consumed += len(line)
                    if consumed > 16*1024*1024: raise ValueError('reference HTTP response too large')
                    if not line.strip() and data:
                        envelope = json.loads('\n'.join(data)); data = []
                        if envelope.get('id') == message.get('id'): return envelope
                    elif line.startswith(b'data:'): data.append(line[5:].decode().strip())
                raise EOFError('SSE ended before matched response')
            body = response.read(16*1024*1024+1)
            if len(body) > 16*1024*1024: raise ValueError('reference HTTP response too large')
            return json.loads(body) if body else None

    def request(self, method, params=None):
        self.counter += 1
        message = {'jsonrpc': '2.0', 'id': self.counter, 'method': method}
        if params is not None: message['params'] = params
        response = self.send(message)
        if self.owned:
            deadline = time.monotonic()+30
            while True:
                response = self.messages.get(timeout=max(.01, deadline-time.monotonic()))
                if isinstance(response, Exception): raise response
                if 'method' in response and 'id' in response:
                    result = {'roots': []} if response['method'] == 'roots/list' else {}
                    self.send({'jsonrpc': '2.0', 'id': response['id'], 'result': result}); continue
                if response.get('id') == self.counter: break
        if not response or response.get('id') != self.counter or 'error' in response:
            raise AssertionError(f'reference request failed: {method}: {response}')
        self.transcript.append({'direction': 'response', 'message': response})
        return response['result']

    def collect(self):
        initialized = self.request('initialize', {'protocolVersion': self.protocol, 'capabilities': {},
                                   'clientInfo': {'name': 'sentinel-independent-wire-probe', 'version': '1'}})
        self.protocol = initialized['protocolVersion']
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools = []; cursor = None; seen = set()
        for page in range(100):
            result = self.request('tools/list', {'cursor': cursor} if cursor else {})
            tools.extend(result['tools']); cursor = result.get('nextCursor')
            if cursor is None: break
            if not cursor or cursor in seen: raise AssertionError('reference cursor repeated/empty')
            seen.add(cursor)
        else: raise AssertionError('reference exceeded 100 pages')
        return {'initialize': initialized, 'tools': tools, 'pages': page+1}

    def close(self):
        try:
            if self.owned: self.owned.finish(graceful=True)
            elif self.session:
                request = urllib.request.Request(self.config['url'], method='DELETE', headers={
                    'Mcp-Session-Id': self.session, 'MCP-Protocol-Version': self.protocol})
                try:
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5): pass
                except urllib.error.HTTPError as error:
                    if error.code not in (404,405): raise
        finally: save(self.directory / 'wire.json', self.transcript)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


def wait_port(port, timeout=20):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2): return
        except OSError: time.sleep(.05)
    raise TimeoutError('HTTP service did not become ready')


def _exit_cleanup():
    for owned in list(_OWNED):
        with contextlib.suppress(Exception):
            owned.cleanup(); owned.finish()


atexit.register(_exit_cleanup)
