#!/usr/bin/env python3
"""Measure complete CLI scans of the tested JAR with explicit metric scopes."""
from __future__ import annotations
import argparse
import ctypes
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys
import threading
import time

import psutil
from interop_support import ROOT, OwnedProcess, free_port, wait_port, java_command, load, run, save, sha, source_identity


def windows_peak(process):
    if os.name!='nt': return None
    class Counters(ctypes.Structure):
        _fields_=[('cb',ctypes.c_ulong),('PageFaultCount',ctypes.c_ulong)]+[(name,ctypes.c_size_t) for name in
          ['PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage']]
    counters=Counters(); counters.cb=ctypes.sizeof(counters)
    function=ctypes.WinDLL('psapi').GetProcessMemoryInfo
    function.argtypes=[ctypes.c_void_p,ctypes.POINTER(Counters),ctypes.c_ulong]; function.restype=ctypes.c_int
    if not function(int(process._handle),ctypes.byref(counters),counters.cb): raise ctypes.WinError()
    return counters.PeakWorkingSetSize


def sample(command, directory, expected):
    start=time.perf_counter(); owned=OwnedProcess(command,directory)
    stop=threading.Event(); maxima={'treeRssSampledMaxBytes':0}; samples=0
    def observe():
        nonlocal samples
        while not stop.wait(.02):
            total=0
            for process in list(owned.tracked.values()):
                try: total+=process.memory_info().rss
                except psutil.Error: pass
            maxima['treeRssSampledMaxBytes']=max(maxima['treeRssSampledMaxBytes'],total); samples+=1
    watcher=threading.Thread(target=observe,daemon=True); watcher.start()
    try:
        code=owned.process.wait(timeout=120)
        peak=windows_peak(owned.process)
    except BaseException:
        owned.cleanup(); raise
    finally:
        stop.set(); watcher.join(timeout=2); owned.finish()
    memory=load(Path(directory)/'memory.json')
    peak=peak if peak is not None else memory['linuxVmHwmKiB']*1024
    value={'exitCode':code,'elapsedSeconds':time.perf_counter()-start,'rootPeakRssBytes':peak,
            'cliBodySeconds':memory['cliBodyNanos']/1e9,'sampleCount':samples,**maxima}
    save(Path(directory)/'measurement.json',value)
    assert code==expected, (directory,code,expected)
    return value


def boundaries(out,jar):
    out.mkdir(parents=True,exist_ok=True); java=java_command(jar)
    schema={'type':'object','additionalProperties':False}
    spec=save(out/'server.json',{'serverName':'limits','tools':[{'name':f't{i}','inputSchema':schema} for i in range(2)]})
    config=save(out/'count-config.json',{'server':'limits','command':sys.executable,
        'args':[str(ROOT/'scripts/benchmark_server.py'),'--spec',str(spec)],'maxTools':1})
    results=[run([*java,'scan','--config',str(config),'--risk-only'],out/'count',expected=(2,))]
    large=out/'oversized-config.json'
    with large.open('wb') as stream: stream.truncate(32*1024*1024+1)
    results.append(run([*java,'scan','--config',str(large),'--risk-only'],out/'file-size',expected=(1,)))
    for mode in ('hang','blocked-write'):
        pidfile=out/(mode+'.pids')
        config=save(out/(mode+'.config.json'),{'server':'limits','command':java[0],
            'args':['-cp',os.pathsep.join([str(ROOT/'target/test-classes'),str(jar)]),
                    'io.github.xiaoxusop.mcpsentinel.ResourceMcpServer',mode,str(pidfile)],
            'connectTimeoutSeconds':1,'requestTimeoutSeconds':1})
        call=run([*java,'scan','--config',str(config),'--risk-only'],out/mode,expected=(2,))
        assert call['elapsedSeconds']<8,call
        pids=[int(value) for value in pidfile.read_text().splitlines()]
        assert all(not psutil.pid_exists(pid) for pid in pids),pids
        call['verifiedEndedPids']=pids; results.append(call)
    save(out/'summary.json',{'checks':results,'status':'passed','timeoutObservationLimitSeconds':8})
    print('Four boundary failures passed: count, file size, hanging tree, blocked write.',flush=True)


def measure(args):
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=True); jar=args.jar.resolve(); java=java_command(jar)
    classes=out/'classes'; classes.mkdir(exist_ok=True)
    javac=str(Path(java[0]).with_name('javac.exe' if os.name=='nt' else 'javac')) if os.environ.get('JAVA_HOME') else 'javac'
    run([javac,'-encoding','UTF-8','-cp',str(jar),'-d',str(classes),str(ROOT/'scripts/ValidationFixtures.java'),str(ROOT/'scripts/MeasureLauncher.java')],out/'compile')
    cp=os.pathsep.join([str(classes),str(jar)])
    run([java[0],'-cp',cp,'ValidationFixtures',str(out/'fixtures')],out/'generate')
    scenarios=[]; servers=[]
    for count in (100,1000):
        for noisy in (False,True):
            stem=f'synthetic-{count}-{str(noisy).lower()}'
            scenarios.append((f'offline-{count}-{noisy}',['--snapshot',str(out/'fixtures'/f'{stem}.snapshot.json'),'--baseline',str(out/'fixtures'/f'{stem}.baseline.json')],3 if noisy else 0))
        stem=f'synthetic-{count}-false'; snapshot=load(out/'fixtures'/f'{stem}.snapshot.json')
        spec=save(out/'fixtures'/f'{count}.server.json',{'serverName':stem,'tools':snapshot['tools']})
        stdio=save(out/'fixtures'/f'{count}.stdio.json',{'server':stem,'command':sys.executable,'args':[str(ROOT/'scripts/benchmark_server.py'),'--spec',str(spec)]})
        port=free_port(); server=OwnedProcess([sys.executable,str(ROOT/'scripts/benchmark_server.py'),'--spec',str(spec),'--port',str(port)],out/f'http-server-{count}')
        servers.append(server); wait_port(port)
        http=save(out/'fixtures'/f'{count}.http.json',{'server':stem,'transport':'streamable-http','url':f'http://127.0.0.1:{port}/mcp'})
        for transport, config in [('stdio',stdio),('http',http)]:
            baseline=out/'fixtures'/f'{count}.{transport}.baseline.json'
            run([*java,'lock','--config',str(config),'--out',str(baseline)],out/f'lock-{count}-{transport}')
            scenarios.append((f'{transport}-{count}',['--config',str(config),'--baseline',str(baseline)],0))
    # Public implementations are separate from the synthetic fixed-size baseline.
    if args.interop:
        directory=args.interop.resolve()/'filesystem-stdio'
        scenarios.append(('external-filesystem',['--config',str(directory/'config.json'),'--baseline',str(directory/'baseline.json')],0))
        node=shutil.which('node'); port=free_port()
        server=OwnedProcess([node,str(ROOT/'validation/interop/node_modules/@playwright/mcp/cli.js'),'--headless','--isolated','--host','127.0.0.1','--allowed-hosts',f'127.0.0.1:{port}','--port',str(port)],out/'external-http-server')
        servers.append(server); wait_port(port)
        config=save(out/'fixtures/external-http.json',{'server':'external-playwright','transport':'streamable-http','url':f'http://127.0.0.1:{port}/mcp'})
        baseline=out/'fixtures/external-http.baseline.json'
        run([*java,'lock','--config',str(config),'--out',str(baseline)],out/'lock-external-http')
        scenarios.append(('external-playwright-http',['--config',str(config),'--baseline',str(baseline)],0))
    results=[]
    try:
        for name,source,expected in scenarios:
            measurements=[]
            for index in range(args.warmups+args.repetitions):
                directory=out/name/str(index); directory.mkdir(parents=True,exist_ok=True)
                command=[java[0],'-Xms64m','-Xmx512m','-cp',cp,'io.github.xiaoxusop.mcpsentinel.cli.MeasureLauncher',str(directory/'memory.json'),
                         'scan',*source,'--json',str(directory/'report.json'),'--sarif',str(directory/'report.sarif')]
                value=sample(command,directory,expected); value['warmup']=index<args.warmups
                measurements.append(value); save(out/name/'samples.json',measurements)
            actual=measurements[args.warmups:]; times=sorted(x['elapsedSeconds'] for x in actual)
            results.append({'scenario':name,'measured':len(actual),'medianSeconds':statistics.median(times),
                'p95Seconds':times[math.ceil(.95*len(times))-1],'maxRootPeakRssBytes':max(x['rootPeakRssBytes'] for x in actual),
                'maxTreeSampledRssBytes':max(x['treeRssSampledMaxBytes'] for x in actual),'samplesSha256':sha(out/name/'samples.json')})
            save(out/'summary.json',{**source_identity(),'platform':platform.platform(),'jarSha256':sha(jar),'jvm':['-Xms64m','-Xmx512m'],
                'warmups':args.warmups,'repetitions':args.repetitions,'p95Method':'nearest rank',
                'adapter':'tested JAR Main.run; adapter reports memory after reports are written',
                'rootPeakScope':'Windows native lifetime PeakWorkingSetSize; Linux VmHWM at CLI completion before teardown',
                'treeMetric':'20ms sampled concurrent RSS sum; may miss short peaks; excludes independently owned HTTP server',
                'scenarios':results,'stableRelease':'BLOCKED'})
            print(f'{name}: {len(actual)} measured scans, median={statistics.median(times):.3f}s',flush=True)
        # Same synthetic stdio configuration, thirty independent JVMs, PID evidence each time.
        name,source,expected=next(x for x in scenarios if x[0]=='stdio-100')
        for index in range(30): run([*java,'scan',*source],out/'continuous'/str(index),expected=(expected,))
        save(out/'continuous.json',{'runs':30,'toolFailures':0,'ownedProcessLeaks':0})
        boundaries(out/'boundaries',jar)
    finally:
        for server in servers: server.finish(graceful=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--jar',type=Path,default=ROOT/'target/mcp-sentinel.jar')
    parser.add_argument('--output',type=Path,default=ROOT/'target/performance'); parser.add_argument('--interop',type=Path)
    parser.add_argument('--warmups',type=int,default=3); parser.add_argument('--repetitions',type=int,default=20)
    parser.add_argument('--boundaries-only',action='store_true')
    args=parser.parse_args(); assert args.warmups>=0 and args.repetitions>=1
    if args.boundaries_only: boundaries(args.output.resolve(),args.jar.resolve())
    else: measure(args)
