#!/usr/bin/env python3
"""Five actual-JAR steps demonstrate review, approval and explicit failure."""
import argparse
import os
from pathlib import Path
from interop_support import ROOT, java_command, load, run, save, sha


def demo(args):
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=True); java=java_command(args.jar)
    javac=str(Path(java[0]).with_name('javac.exe' if os.name=='nt' else 'javac')) if os.environ.get('JAVA_HOME') else 'javac'
    classes=out/'classes'; classes.mkdir(exist_ok=True); cp=os.pathsep.join([str(classes),str(args.jar.resolve())])
    run([javac,'-encoding','UTF-8','-cp',str(args.jar.resolve()),'-d',str(classes),str(ROOT/'scripts/ValidationFixtures.java')],out/'compile')
    run([java[0],'-cp',cp,'ValidationFixtures',str(out/'seed')],out/'seed-generate')
    initial=out/'seed/synthetic-100-false.snapshot.json'
    run([java[0],'-cp',cp,'ValidationFixtures',str(out/'inputs'),str(initial)],out/'inputs-generate')
    baseline=out/'inputs/baseline.json'; changed=out/'inputs/changed.json'
    before=load(baseline)['surfaceFingerprint']; after=load(changed)['surfaceFingerprint']; calls=[]
    for name,snapshot,expected,extra in [('01-clean',initial,0,[]),('02-drift',changed,4,[]),
          ('03-approve',changed,0,['--accept-changes','--expect-baseline',before,'--expect-surface',after]),
          ('04-approved',changed,0,[]),('05-missing-baseline',changed,5,[])]:
        base=out/'missing.json' if name.startswith('05') else baseline
        report=out/(name+'.json')
        calls.append(run([*java,'scan','--snapshot',str(snapshot),'--baseline',str(base),'--json',str(report),*extra],out/name,expected=(expected,)))
        doc=load(report); assert doc['reportVersion']==3
        if name.startswith('05'): assert doc['checks']=={'staticRisk':'NOT_RUN','drift':'NOT_RUN'}
    save(out/'summary.json',{'jarSha256':sha(args.jar),'steps':calls,'inputKind':'synthetic offline data',
         'independentUserReplay':'PENDING','stableRelease':'BLOCKED'})
    print('Five candidate demo steps passed: clean, drift, approve, approved, failed check.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--jar',type=Path,default=ROOT/'target/mcp-sentinel.jar')
    parser.add_argument('--output',type=Path,default=ROOT/'target/candidate-demo'); demo(parser.parse_args())
