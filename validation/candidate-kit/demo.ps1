param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('init','review','approve','rescan','missing')]
    [string]$Step,
    [string]$BaselineFingerprint,
    [string]$SurfaceFingerprint
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Output 'Java 21 is required.'
    exit 1
}
# PowerShell 7 retains native stderr as output when explicitly redirected.
$ErrorActionPreference = 'Continue'
$version = (& java -version 2>&1 | Out-String)
$versionExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($versionExit -ne 0 -or $version -notmatch 'version "21\.') {
    Write-Output 'Use Java 21 for this candidate.'
    exit 1
}
switch ($Step) {
    'init' {
        New-Item -ItemType Directory -Force -Path work | Out-Null
        Copy-Item -LiteralPath examples/baseline.json -Destination work/baseline.json
        & java -jar mcp-sentinel.jar scan --snapshot examples/before.json --baseline work/baseline.json --json work/01-clean.json
    }
    'review' {
        & java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --json work/02-drift.json
    }
    'approve' {
        if (-not $BaselineFingerprint -or -not $SurfaceFingerprint) {
            Write-Output 'Supply BaselineFingerprint and SurfaceFingerprint from the reviewed report.'
            exit 1
        }
        & java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --accept-changes --expect-baseline $BaselineFingerprint --expect-surface $SurfaceFingerprint --json work/03-approve.json
    }
    'rescan' {
        & java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/baseline.json --json work/04-approved.json
    }
    'missing' {
        & java -jar mcp-sentinel.jar scan --snapshot examples/changed.json --baseline work/does-not-exist.json --json work/05-missing.json
    }
}
exit $LASTEXITCODE
