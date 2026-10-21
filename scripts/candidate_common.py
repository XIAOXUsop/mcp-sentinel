"""Small, fail-closed primitives shared by trusted candidate jobs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / 'validation/release-policy.json'
IDENTITY_ENV = {
    'repository': 'GITHUB_REPOSITORY', 'commit': 'GITHUB_SHA',
    'workflowRef': 'GITHUB_WORKFLOW_REF', 'runId': 'GITHUB_RUN_ID',
    'runAttempt': 'GITHUB_RUN_ATTEMPT', 'event': 'GITHUB_EVENT_NAME', 'ref': 'GITHUB_REF',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return path


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def identity():
    value = {key: os.environ.get(env, '') for key, env in IDENTITY_ENV.items()}
    require(all(value.values()), 'Candidate acceptance requires a complete CI run identity')
    require(re.fullmatch(r'[0-9a-f]{40}', value['commit']), 'Invalid commit identity')
    require(value['runId'].isdigit() and value['runAttempt'].isdigit(), 'Invalid run identity')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    require(head == value['commit'], 'Checked-out source differs from the candidate commit')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip(),
            'Candidate source checkout is dirty')
    return value


def policy(path=POLICY):
    value = load(path)
    require(type(value.get('policyVersion')) is int and value['policyVersion'] == 1 and
            type(value.get('stablePublicationAllowed')) is bool,
            'Missing or invalid stable publication policy')
    require(value.get('repository') == 'XIAOXUsop/mcp-sentinel', 'Wrong policy repository')
    return value


def require_stable_allowed(path=POLICY):
    value = policy(path)
    require(value['stablePublicationAllowed'] is True, 'Stable publication remains blocked by the recorded user decision')
    return value


def source_inputs():
    paths = subprocess.check_output(['git', 'ls-files', 'scripts', 'schemas', 'validation',
                                     '.github', 'pom.xml'], cwd=ROOT, text=True).splitlines()
    return {path: sha(ROOT / path) for path in paths}


def child(root, name):
    require(isinstance(name, str) and name and '\\' not in name, 'Invalid evidence path')
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts and ':' not in name, 'Evidence path escapes its root')
    result = (Path(root) / path).resolve()
    require(result.is_relative_to(Path(root).resolve()), 'Evidence symlink escapes its root')
    return result


def check_files(root, files):
    require(isinstance(files, dict) and files, 'Missing evidence file inventory')
    for name, digest in files.items():
        require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest), 'Invalid file digest')
        path = child(root, name)
        require(path.is_file() and sha(path) == digest, f'Evidence file missing or changed: {name}')


def read_indexed(root, files, name):
    require(name in files, f'Unindexed required evidence: {name}')
    return load(child(root, name))
