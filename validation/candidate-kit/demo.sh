#!/bin/sh
# Explicit offline steps. Approve requires the two fingerprints from the review.
set -eu
case "$0" in */*) cd -- "${0%/*}" ;; esac
command -v java >/dev/null 2>&1 || { echo "Java 21 is required."; exit 1; }
version=$(java -version 2>&1) || exit 1
case "$version" in *'version "21.'*) ;; *) echo "Use Java 21 for this candidate."; exit 1 ;; esac
step=${1:-help}
case "$step" in
  init) /bin/mkdir -p work; /bin/cp examples/baseline.json work/baseline.json
        java -jar mcp-sentinel.jar scan --snapshot examples/before.json --baseline work/baseline.json --json work/01-clean.json ;;
  review) java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --json work/02-drift.json ;;
  approve) [ "$#" -eq 3 ] || { echo "Usage: demo.sh approve BASELINE_FINGERPRINT SURFACE_FINGERPRINT"; exit 1; }
        java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --accept-changes --expect-baseline "$2" --expect-surface "$3" --json work/03-approve.json ;;
  rescan) java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --json work/04-approved.json ;;
  missing) java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/does-not-exist.json --json work/05-missing.json ;;
  *) echo "Steps: init, review, approve BASELINE_FINGERPRINT SURFACE_FINGERPRINT, rescan, missing"
     exit 1 ;;
esac
