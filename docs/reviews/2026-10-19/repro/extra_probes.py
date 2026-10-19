import json
import os
from pathlib import Path
import shutil
import subprocess
from jsonschema import Draft202012Validator
SOURCE = Path(__file__).resolve().parent
R = SOURCE.parents[3]
H = R/'target/review-2026-10-19'
H.mkdir(parents=True,exist_ok=True)
J = Path(os.environ['JAVA_HOME'])/'bin'/('java.exe' if os.name == 'nt' else 'java') if os.environ.get('JAVA_HOME') else Path(shutil.which('java') or 'java').resolve()
jar = R/'target/mcp-sentinel.jar'
subprocess.run([str(J.with_name('javac.exe' if os.name == 'nt' else 'javac')), '-encoding','UTF-8','-cp',str(jar),'-d',str(H),str(SOURCE/'ReviewFixtures.java')], check=True)
# A distinct subdirectory preserves the first run's original baseline fixtures.
out = H/'extra'; out.mkdir(exist_ok=True)
subprocess.run([str(J),'-cp',str(H)+os.pathsep+str(jar),'ReviewFixtures',str(out)], check=True)
results = {}
for name, options in [('spaced-server',[]), ('open-implicit',['--fail-on','MEDIUM']), ('open-explicit',['--fail-on','MEDIUM']), ('unknown-annotation-offline',[])]:
    snap = out/(name+'.json' if name.endswith('offline') else name+'-snapshot.json')
    report = out/(name+'-report.json')
    p = subprocess.run([str(J),'-jar',str(jar),'scan','--snapshot',str(snap),'--risk-only','--json',str(report),*options],
                       cwd=R,text=True,encoding='utf-8',capture_output=True,timeout=20)
    (out/(name+'.stdout.txt')).write_text(p.stdout,encoding='utf-8')
    (out/(name+'.stderr.txt')).write_text(p.stderr,encoding='utf-8')
    data = json.loads(report.read_text(encoding='utf-8'))
    results[name] = {'exitCode':p.returncode, 'findings':data['findings']}
contract = json.loads((R/'schemas/scan-report-v2.schema.json').read_text(encoding='utf-8'))
reports = sorted(H.glob('*-report.json')) + sorted(out.glob('*-report.json')) + list(H.glob('*/report.json'))
for path in reports:
    Draft202012Validator(contract).validate(json.loads(path.read_text(encoding='utf-8')))
results['reviewReportsPassingSchema'] = len(reports)
(H/'extra-probe-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(results,ensure_ascii=False,indent=2))
