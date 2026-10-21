"""Scan tracked source bytes, including binary-marked files; never print matches."""
import re
import subprocess
import sys
from candidate_common import ROOT

PATTERN = re.compile(rb"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_-]{16,})")

if __name__ == '__main__':
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    matched = [p for p in paths if p and not p.endswith('.lock') and PATTERN.search((ROOT / p).read_bytes())]
    print(f'Secret scan: {len(matched)} tracked files with suspect material (contents suppressed)')
    sys.exit(1 if matched else 0)
