$ErrorActionPreference = "Stop"

Write-Host "CarbonStackComms Rust artifact guard"
Write-Host "===================================="

$Patterns = @(
    "target/",
    ".fingerprint/",
    "/debug/",
    "/release/",
    ".exe",
    ".pdb",
    ".o",
    ".rlib",
    ".rmeta"
)

$Tracked = git ls-files

$Hits = @()

foreach ($File in $Tracked) {
    $Normalized = $File -replace "\\", "/"

    foreach ($Pattern in $Patterns) {
        if ($Normalized.Contains($Pattern)) {
            $Hits += $File
            break
        }
    }
}

if ($Hits.Count -gt 0) {
    Write-Host ""
    Write-Host "FAIL: generated Rust/build artifacts are tracked by git:"
    $Hits | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    Write-Host "Remove them from git tracking before pushing:"
    Write-Host "  git rm -r --cached --ignore-unmatch -- internal/protocol/mls/research/openmls-minimal/target"
    exit 1
}

Write-Host "PASS: no tracked Rust/build artifacts found"
