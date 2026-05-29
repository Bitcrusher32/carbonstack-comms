param(
    [switch]$Full
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

Write-Host "CarbonStack OpenMLS backbone self-test harness"
Write-Host ""
Write-Host "Status:"
Write-Host "  Experimental local self-test only."
Write-Host "  Not a production deployment script."
Write-Host "  Not a finished messenger."
Write-Host "  Not production E2EE."
Write-Host "  Not hostile-server complete."
Write-Host "  Not metadata-private."
Write-Host "  Not Android-ready."
Write-Host "  Not externally audited or certified secure."
Write-Host ""
Write-Host "This self-test validates the current known-good local backbone:"
Write-Host "  CarbonStackComms OpenMLS sidecar"
Write-Host "  + CarbonStackCypher real local server"
Write-Host "  + opaque OpenMLS artifact envelope relay"
Write-Host "  + payload metadata validation"
Write-Host "  + consume-then-ack semantics"
Write-Host ""
Write-Host "It delegates execution to:"
Write-Host "  scripts/smoke-openmls-real-cypher-relay.ps1"
Write-Host ""

$SmokeArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\scripts\smoke-openmls-real-cypher-relay.ps1"
)

if ($Full) {
    Write-Host "Mode:"
    Write-Host "  Full validation"
    Write-Host ""
    $SmokeArgs += "-Full"
}
else {
    Write-Host "Mode:"
    Write-Host "  Targeted backbone self-test"
    Write-Host ""
}

& powershell @SmokeArgs

if ($LASTEXITCODE -ne 0) {
    throw "OpenMLS backbone self-test failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "OpenMLS backbone self-test completed successfully."
Write-Host ""
Write-Host "Boundary:"
Write-Host "  This proves a repeatable local experimental backbone lifecycle."
Write-Host "  It does not prove production readiness, hostile-server safety, metadata privacy, Android readiness, or external audit."
