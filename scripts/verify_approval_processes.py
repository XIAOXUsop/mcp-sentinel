#!/usr/bin/env python3
"""Real processes exercise CLI approval races and checked atomic-write interruption."""
import argparse
import os
from pathlib import Path
import shutil
import sys
import time
from interop_support import ROOT, OwnedProcess, java_command, load, run, save, sha


def wait_file(path):
    deadline=time.monotonic()+20
    while not path.exists():
        if time.monotonic()>deadline: raise TimeoutError(f'missing synchronization marker: {path.name}')
        time.sleep(.01)


def verify(args):
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=True); jar=args.jar.resolve(); java=java_command(jar)
    classes=out/'classes'; classes.mkdir(exist_ok=True)
    javac=str(Path(java[0]).with_name('javac.exe' if os.name=='nt' else 'javac')) if os.environ.get('JAVA_HOME') else 'javac'
    run([javac,'-encoding','UTF-8','-cp',str(jar),'-d',str(classes),*[str(ROOT/'scripts'/f) for f in ['ValidationFixtures.java','AtomicWriteProbe.java','ApprovalBarrierLauncher.java']]],out/'compile')
    cp=os.pathsep.join([str(classes),str(jar)])
    run([java[0],'-cp',cp,'ValidationFixtures',str(out/'seed')],out/'seed-generate')
    initial=out/'seed/synthetic-100-false.snapshot.json'
    run([java[0],'-cp',cp,'ValidationFixtures',str(out/'inputs'),str(initial)],out/'inputs-generate')
    trusted=out/'inputs/baseline.json'; candidate=out/'inputs/candidate-baseline.json'; changed=out/'inputs/changed.json'
    checks=[]
    for phase in ['before','after']:
        directory=out/f'interrupt-{phase}'; directory.mkdir(exist_ok=True)
        target=directory/'baseline.json'; shutil.copyfile(trusted,target); marker=directory/'ready'
        owned=OwnedProcess([java[0],'-cp',cp,'AtomicWriteProbe',phase,str(target),str(candidate),str(marker)],directory/'process')
        try: wait_file(marker)
        finally: owned.cleanup(); owned.finish()
        assert sha(target)==sha(trusted if phase=='before' else candidate)
        snapshot=initial if phase=='before' else changed
        run([*java,'scan','--snapshot',str(snapshot),'--baseline',str(target)],directory/'validate',expected=(0,))
        checks.append({'case':'interrupt-'+phase,'status':'passed','result':'complete-old' if phase=='before' else 'complete-new','baselineSha256':sha(target)})
    directory=out/'race'; directory.mkdir(exist_ok=True)
    target=directory/'baseline.json'; shutil.copyfile(trusted,target); gate=directory/'go'
    commands=[]; processes=[]
    common=['scan','--snapshot',str(changed),'--baseline',str(target),'--accept-changes',
            '--expect-baseline',load(trusted)['surfaceFingerprint'],'--expect-surface',load(changed)['surfaceFingerprint']]
    try:
        for index in range(2):
            ready=directory/f'ready-{index}'
            process=OwnedProcess([java[0],'-cp',cp,'io.github.xiaoxusop.mcpsentinel.cli.ApprovalBarrierLauncher',str(ready),str(gate),*common],directory/str(index))
            processes.append(process); wait_file(ready)
        gate.write_text('go',encoding='utf-8')
        codes=[p.process.wait(timeout=30) for p in processes]
        assert sorted(codes)==[0,5],codes
    finally:
        for p in processes:
            if p.process.poll() is None: p.cleanup()
            p.finish()
    baseline=load(target); assert baseline['surfaceFingerprint']==load(changed)['surfaceFingerprint']
    assert baseline['acceptedChanges'] and all(c['beforeFingerprint']==load(trusted)['surfaceFingerprint'] and c['afterFingerprint']==baseline['surfaceFingerprint'] for c in baseline['acceptedChanges'])
    run([*java,'scan','--snapshot',str(changed),'--baseline',str(target)],directory/'validate',expected=(0,))
    checks.append({'case':'independent-cli-approval-race','status':'passed','exitCodes':codes,'acceptedChanges':len(baseline['acceptedChanges'])})
    before=sha(trusted)
    for name,snapshot,baseline,expected in [('trusted-comparison',changed,trusted,4),('candidate-self-baseline',changed,candidate,0)]:
        run([*java,'scan','--snapshot',str(snapshot),'--baseline',str(baseline)],out/name,expected=(expected,))
        checks.append({'case':name,'exitCode':expected,'status':'passed'})
    run([*java,'scan','--snapshot',str(changed),'--baseline',str(trusted),'--accept-changes','--expect-baseline','0'*64,'--expect-surface',load(changed)['surfaceFingerprint']],out/'stale-approval',expected=(5,))
    assert sha(trusted)==before
    checks.append({'case':'stale-approval-preserves-baseline','status':'passed'})
    not_directory=out/'regular-file'; not_directory.write_text('occupied',encoding='utf-8')
    run([*java,'scan','--snapshot',str(initial),'--baseline',str(trusted),'--json',str(not_directory/'report.json')],out/'failed-output',expected=(6,))
    assert sha(trusted)==before
    checks.append({'case':'output-failure-preserves-baseline','status':'passed'})
    save(out/'summary.json',{'platform':sys.platform,'jarSha256':sha(jar),'checks':checks,
        'interruptScope':'process termination at checked temporary file / completed replacement; not power-loss durability',
        'sarifUpload':'SEE_SEPARATE_CONTROLLED_INGESTION_JOB','stableRelease':'BLOCKED'})
    print(f'{len(checks)} approval/workflow process checks passed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--jar',type=Path,default=ROOT/'target/mcp-sentinel.jar')
    parser.add_argument('--output',type=Path,default=ROOT/'target/approval-processes'); verify(parser.parse_args())
