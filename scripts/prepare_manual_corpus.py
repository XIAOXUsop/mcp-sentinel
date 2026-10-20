#!/usr/bin/env python3
"""Select public declarations deterministically; leave every human label empty."""
import argparse
import hashlib
from pathlib import Path
from interop_support import ROOT, load, save, sha


def prepare(source,output):
    manifest=load(ROOT/'validation/interop/manifest.json'); records=[]
    for service in ['filesystem','git']:
        evidence=source/f'{service}-stdio/reference-tools.json'
        original=load(evidence)
        version=next(s['version'] for s in manifest['services'] if s['id']==service)
        for tool in sorted(original['tools'],key=lambda t:t['name']):
            if len(records)==20: break
            identity=f'{service}:{version}:{tool["name"]}'
            identifier=hashlib.sha256(identity.encode()).hexdigest()[:16]
            path=save(output/'declarations'/f'{identifier}.json',tool)
            records.append({'sampleId':identifier,'service':service,'version':version,'tool':tool['name'],
                'group':'modelcontextprotocol/servers','split':'development','declaration':str(path.relative_to(output)),
                'declarationSha256':sha(path),'sourceEvidenceSha256':sha(evidence),
                'sourceKind':'public-package-wire-declaration','redistributionReview':'PENDING',
                'reviews':[],'adjudication':None})
    assert len(records)==20
    save(output/'samples.json',{'datasetVersion':1,'samples':records,'humanLabels':0,'holdoutSamples':0,
          'sourceGroups':sorted({r['group'] for r in records}),'serviceSources':sorted({r['service'] for r in records}),
          'status':'AWAITING_INDEPENDENT_HUMAN_REVIEW',
          'limitations':['20 development declarations; not the 200-sample target','two service packages from one upstream repository; not ten-source coverage',
                         'no accuracy or false-positive estimate','raw declarations stay local until redistribution review']})
    save(output/'review-template.json',{'sampleId':'REPLACE_WITH_SAMPLE_ID','reviewerId':'','role':'',
        'independentOfRuleImplementation':None,'reviewedAt':'','label':'UNLABELED',
        'expectedFindings':[],'rationale':'','sawScannerOutputBeforeLabeling':None})
    print('Prepared 20 public-source development declarations; human labels=0; evaluation remains pending.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--interop',type=Path,default=ROOT/'target/interop')
    parser.add_argument('--output',type=Path,default=ROOT/'target/manual-corpus'); args=parser.parse_args()
    prepare(args.interop.resolve(),args.output.resolve())
