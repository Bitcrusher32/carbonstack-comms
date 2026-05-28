param(
    [switch]$Full
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

Write-Host "CarbonStackComms OpenMLS real-Cypher relay smoke harness"
Write-Host ""
Write-Host "Status:"
Write-Host "  Experimental/dev harness only."
Write-Host "  Not production E2EE."
Write-Host "  Not certified secure."
Write-Host "  Not polished Comms runtime UX."
Write-Host ""
Write-Host "This harness runs the v0.2.56 real-server proof:"
Write-Host "  TestOpenMLSSidecarFullLifecycleRelayThroughRealCypherServer"
Write-Host ""
Write-Host "It will:"
Write-Host "  build a temp carbonstack-cypher test binary"
Write-Host "  start a real Cypher server on localhost"
Write-Host "  use a temp SQLite DB"
Write-Host "  run OpenMLS KeyPackage -> Welcome -> application-message relay"
Write-Host "  verify final sidecar message-open plaintext recovery"
Write-Host ""

$StaleCypher = Get-Process cypher -ErrorAction SilentlyContinue
if ($StaleCypher) {
    Write-Host "WARNING: existing cypher processes detected:"
    $StaleCypher | Select-Object Id, ProcessName, Path | Format-Table | Out-String | Write-Host
    Write-Host "Refusing to continue while cypher processes are already running."
    Write-Host "Stop stale test processes manually if appropriate:"
    Write-Host "  Get-Process cypher -ErrorAction SilentlyContinue | Stop-Process -Force"
    exit 1
}

Write-Host "Running targeted real-Cypher relay lifecycle smoke test..."
Invoke-NativeCommand go test -p 1 ./internal/protocol -run "TestOpenMLSSidecarFullLifecycleRelayThroughRealCypherServer" -count=1 -timeout 240s

Write-Host ""
Write-Host "Running generated Rust/OpenMLS artifact guard..."
Invoke-NativeCommand powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

if ($Full) {
    Write-Host ""
    Write-Host "Running broader protocol/relay validation because -Full was provided..."

    Invoke-NativeCommand go test -p 1 ./internal/protocol -run "TestOpenMLSSidecarFullLifecycleRelayThroughCypherEnvelope|TestOpenMLSSidecarFullLifecycleRelayThroughRealCypherServer" -count=1 -timeout 300s
    Invoke-NativeCommand go test -p 1 ./internal/relay
    Invoke-NativeCommand go test -p 1 ./internal/protocol -count=1 -timeout 360s
    Invoke-NativeCommand go test -p 1 ./... -count=1 -timeout 360s

    Write-Host ""
    Write-Host "Running generated Rust/OpenMLS artifact guard again after full validation..."
    Invoke-NativeCommand powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1
}

Write-Host ""
Write-Host "Smoke harness completed successfully."
Write-Host ""
Write-Host "Reminder:"
Write-Host "  This proves an experimental local dev/test relay lifecycle."
Write-Host "  It does not prove production readiness, hostile-server safety, metadata minimization, Android readiness, or external audit."

