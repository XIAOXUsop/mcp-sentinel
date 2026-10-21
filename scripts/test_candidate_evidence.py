"""Fault injection: plausible incomplete or mixed-run evidence must never authorize handoff."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_candidate_evidence as gate
from candidate_common import check_files, load, save, sha, source_inputs

IDENTITY = {'repository':'XIAOXUsop/mcp-sentinel','commit':'a'*40,'runId':'123','runAttempt':'1',
            'workflowRef':'XIAOXUsop/mcp-sentinel/.github/workflows/interop.yml@refs/heads/master',
            'event':'push','ref':'refs/heads/master'}


def fixture(root, platform, inputs):
    """Explicitly synthetic evidence, never used as actual project acceptance."""
    root.mkdir(parents=True)
    (root/'mcp-sentinel.jar').write_bytes(b'synthetic jar')
    (root/'bom.json').write_bytes(b'{}')
    jar=sha(root/'mcp-sentinel.jar'); bom=sha(root/'bom.json')
    build={'commit':IDENTITY['commit'],'platform':platform,'jarSha256':jar,'sbomSha256':bom,
           'reportVersion':3,'cliChecks':33,'calls':[{'exitCode':0,'expectedExit':0}]*33,
           'jsonReportsValidated':24,'sarifFilesValidated':24,'jsonSchemaNegativeChecks':3,'trustRegressionChecks':4}
    save(root/'artifact-verification/build-evidence.json',build)
    (root/'surefire-reports').mkdir()
    (root/'surefire-reports/TEST-synthetic.xml').write_text('<testsuite tests="1" errors="0" failures="0" skipped="0"/>')
    save(root/'python-tests.json',dict(testsRun=1,failures=0,errors=0,skipped=0,expectedFailures=0,unexpectedSuccesses=0))
    save(root/'evaluation/summary.json',dict(comparisons=300,independentWitnessChecks=600,riskProbes=200,failedExpectations=0))
    cells=[dict(cell=name,status='passed',repeats=3,tools=1,referenceProtocol='test',sentinelProtocol='test') for name in sorted(gate.CELLS)]
    common=dict(commit=IDENTITY['commit'],jarSha256=jar,sbomSha256=bom,workingTreeDirty=False)
    save(root/'interop/summary.json',dict(common,platform=platform,cells=cells))
    for name in gate.CELLS:
        for suffix in ('online.report.json','offline.report.json','reference-tools.json','collection-metadata.json'):
            save(root/f'interop/{name}/{suffix}',{})
        save(root/f'interop/{name}/mutated.report.json',{'diff':{'blockingChanges':1},'exitCode':4})
    checks=[dict(case=name,status='passed',exitCodes=[0,5]) for name in gate.APPROVALS]
    save(root/'approval-processes/summary.json',dict(jarSha256=jar,platform=platform,checks=checks))
    save(root/'candidate-demo/summary.json',dict(jarSha256=jar,steps=[{'exitCode':n} for n in [0,4,0,0,5]]))
    save(root/'manual-corpus/samples.json',dict(humanLabels=0,holdoutSamples=0,samples=[{}]*20))
    save(root/'performance/measurement-context.json',common)
    scenarios=[]
    for name in sorted(gate.SCENARIOS):
        expected=3 if name.endswith('-True') else 0
        samples=[dict(warmup=i<3,exitCode=expected,expectedExit=expected,rootPeakRssBytes=10,elapsedSeconds=1) for i in range(23)]
        path=save(root/f'performance/{name}/samples.json',samples)
        scenarios.append(dict(scenario=name,measured=20,samplesSha256=sha(path)))
    save(root/'performance/summary.json',dict(common,warmups=3,repetitions=20,scenarios=scenarios,
         measurementContextSha256=sha(root/'performance/measurement-context.json')))
    save(root/'performance/continuous.json',dict(runs=30,toolFailures=0,ownedProcessLeaks=0))
    for i in range(30):
        save(root/f'performance/continuous/{i}/call.json',dict(exitCode=0))
    save(root/'performance/boundaries/summary.json',dict(status='passed',
         checks=[dict(exitCode=n,elapsedSeconds=1,verifiedEndedPids=[123]) for n in (2,1,2,2)]))
    save(root/'performance/test/process.json',dict(remainingBeforeEmergencyCleanup=[]))
    files={p.relative_to(root).as_posix():sha(p) for p in root.rglob('*') if p.is_file()}
    coverage=gate.platform_checks(root,files,IDENTITY,platform)
    save(root/'platform-receipt.json',dict(evidenceVersion=1,kind='platform',identity=IDENTITY,platform=platform,
         sourceInputs=inputs,stages={s:'success' for s in gate.STAGES},coverage=coverage,files=files))


class CandidateGate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.inputs=source_inputs()
        for p in ('linux','win32'): fixture(self.root/p,p,self.inputs)
        report=save(self.root/'sarif/report.json',dict(exitCode=4,diff={'blockingChanges':1},findings=[]))
        sarif=save(self.root/'sarif/report.sarif',{})
        save(self.root/'sarif/receipt.json',dict(identity=IDENTITY,jarSha256=sha(self.root/'linux/mcp-sentinel.jar'),
             scanOutcome='failure',uploadOutcome='success',files={'report.json':sha(report),'report.sarif':sha(sarif)}))

    def run_gate(self, **kw):
        return gate.verify(self.root, IDENTITY, **kw)

    def rewrite(self, path, change, platform=None):
        data=load(path); change(data); save(path,data)
        if platform:
            receipt=self.root/platform/'platform-receipt.json'
            doc=load(receipt)
            doc['files'][path.relative_to(self.root/platform).as_posix()]=sha(path)
            save(receipt,doc)

    def test_complete_engineering_does_not_authorize_stable_release_or_human_acceptance(self):
        value=self.run_gate()
        self.assertEqual(value['engineeringStatus'],'PASSED')
        self.assertEqual(value['stableReleaseStatus'],'BLOCKED')
        self.assertFalse(value['stablePublicationAllowed'])
        self.assertEqual(value['humanAcceptance']['humanLabels'],0)
        with self.assertRaises(ValueError): self.run_gate(candidate=True)

    def test_wrong_commit_attempt_and_platform_are_rejected(self):
        path=self.root/'win32/platform-receipt.json'; original=load(path)
        for field,value in [('commit','b'*40),('runAttempt','2'),('repository','other/repo')]:
            with self.subTest(field=field):
                doc=copy.deepcopy(original); doc['identity'][field]=value; save(path,doc)
                with self.assertRaisesRegex(ValueError,'identity'): self.run_gate()
        save(path,original)

    def test_skipped_required_stage_is_rejected(self):
        self.rewrite(self.root/'linux/platform-receipt.json',lambda d:d['stages'].update(interop='skipped'))
        with self.assertRaisesRegex(ValueError,'stage'): self.run_gate()

    def test_missing_platform_and_replaced_jar_or_sbom_are_rejected(self):
        for file in ('mcp-sentinel.jar','bom.json'):
            path=self.root/'linux'/file; old=path.read_bytes(); path.write_bytes(b'replaced')
            with self.subTest(file=file), self.assertRaises(ValueError): self.run_gate()
            path.write_bytes(old)
        (self.root/'win32/platform-receipt.json').unlink()
        with self.assertRaises(OSError): self.run_gate()

    def test_cell_and_measurement_count_cannot_be_hidden_by_updated_hash(self):
        for relative,mutation in [
            ('interop/summary.json',lambda d:d['cells'].pop()),
            ('performance/summary.json',lambda d:d.update(repetitions=1)),
            ('approval-processes/summary.json',lambda d:d['checks'][0].update(status='failed')),
            ('performance/test/process.json',lambda d:d.update(remainingBeforeEmergencyCleanup=[123])),
        ]:
            path=self.root/'linux'/relative; original=load(path)
            self.rewrite(path,mutation,'linux')
            with self.subTest(path=relative), self.assertRaises(ValueError): self.run_gate()
            self.rewrite(path,lambda d:(d.clear(),d.update(original)),'linux')

    def test_artifact_upload_is_not_sarif_ingestion(self):
        self.rewrite(self.root/'sarif/receipt.json',lambda d:d.update(uploadOutcome='skipped'))
        with self.assertRaisesRegex(ValueError,'SARIF'): self.run_gate()

    def test_platforms_cannot_substitute_their_own_rebuilt_jar(self):
        root=self.root/'win32'; (root/'mcp-sentinel.jar').write_bytes(b'other build')
        digest=sha(root/'mcp-sentinel.jar')
        for name in ('artifact-verification/build-evidence.json','interop/summary.json','performance/summary.json',
                     'performance/measurement-context.json','candidate-demo/summary.json','approval-processes/summary.json'):
            self.rewrite(root/name,lambda d:d.update(jarSha256=digest),'win32')
        self.rewrite(root/'performance/summary.json',
                     lambda d:d.update(measurementContextSha256=sha(root/'performance/measurement-context.json')),'win32')
        self.rewrite(root/'platform-receipt.json',lambda d:d['files'].update({'mcp-sentinel.jar':digest}))
        with self.assertRaisesRegex(ValueError,'different JAR'): self.run_gate()

    def test_traversal_in_evidence_inventory_is_rejected(self):
        with self.assertRaises(ValueError): check_files(self.root,{'../escape':'a'*64})

    def test_policy_missing_or_invalid_never_allows_summary(self):
        path=self.root/'bad-policy.json'; save(path,{'stablePublicationAllowed':'true'})
        with self.assertRaises(ValueError): self.run_gate(policy_path=path)
        save(path,{'policyVersion':True,'repository':IDENTITY['repository'],'stablePublicationAllowed':False})
        with self.assertRaises(ValueError): self.run_gate(policy_path=path)

    def test_final_receipt_binds_archive_and_both_consumer_runs(self):
        archive=self.root/'bundle/synthetic.zip'; archive.parent.mkdir(); archive.write_bytes(b'synthetic archive')
        for platform in ('linux','win32'):
            trace=save(self.root/f'consumption/{platform}/trace.json',{'synthetic':True})
            save(self.root/f'consumption/{platform}.json',dict(identity=IDENTITY,platform=platform,
                 archiveSha256=sha(archive),jarSha256=sha(self.root/'linux/mcp-sentinel.jar'),
                 status='passed',exitCodes=[0,4,0,0,5],developmentToolsOnPath=[],staleApprovalExit=5,missingJavaExit=1,
                 files={f'{platform}/trace.json':sha(trace)}))
        self.assertEqual(self.run_gate(candidate=True)['candidateStatus'],'READY_FOR_HANDOFF')
        archive.write_bytes(b'replaced')
        with self.assertRaises(ValueError): self.run_gate(candidate=True)
        archive.write_bytes(b'synthetic archive')
        path=self.root/'consumption/win32.json'
        self.rewrite(path,lambda d:d['identity'].update(runAttempt='2'))
        with self.assertRaises(ValueError): self.run_gate(candidate=True)
