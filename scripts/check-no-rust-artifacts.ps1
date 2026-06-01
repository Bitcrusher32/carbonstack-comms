param(
    [switch]$StrictFilesystem
)

$ErrorActionPreference = "Stop"

Write-Host "CarbonStackComms Rust artifact guard"
Write-Host "===================================="

$RepoRoot = Split-Path -Parent $PSScriptRoot

$ForbiddenDirNames = @(
    "target",
    ".carbonstack-openmls-sidecar-state",
    ".go-cache",
    ".go-tmp"
)

$ForbiddenFileNames = @(
    "provider-storage.json",
    "signer.json"
)

$ForbiddenFilePatterns = @(
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*.exe",
    "*.test.exe"
)

function Convert-ToRepoRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetFullPath($RepoRoot)

    if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($root.Length).TrimStart("\", "/")
    }

    return $Path
}

function Test-HasGitMetadata {
    $dotGit = Join-Path $RepoRoot ".git"
    return (Test-Path -LiteralPath $dotGit)
}

function Find-TrackedForbiddenArtifacts {
    $tracked = & git -C $RepoRoot ls-files 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed with exit code $LASTEXITCODE"
    }

    $hits = New-Object System.Collections.Generic.List[string]

    foreach ($path in $tracked) {
        $normalized = $path -replace "\\", "/"
        $leaf = Split-Path $normalized -Leaf

        foreach ($dir in $ForbiddenDirNames) {
            if ($normalized -eq $dir -or $normalized.StartsWith("$dir/") -or $normalized.Contains("/$dir/")) {
                $hits.Add($path)
            }
        }

        foreach ($name in $ForbiddenFileNames) {
            if ($leaf -eq $name) {
                $hits.Add($path)
            }
        }

        if ($normalized.EndsWith(".db") -or
            $normalized.EndsWith(".db-shm") -or
            $normalized.EndsWith(".db-wal") -or
            $normalized.EndsWith(".exe") -or
            $normalized.EndsWith(".test.exe")) {
            $hits.Add($path)
        }
    }

    return $hits | Sort-Object -Unique
}

function Find-FilesystemForbiddenArtifacts {
    $hits = New-Object System.Collections.Generic.List[string]

    foreach ($name in $ForbiddenDirNames) {
        Get-ChildItem $RepoRoot -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $name } |
            ForEach-Object { $hits.Add((Convert-ToRepoRelativePath $_.FullName)) }
    }

    foreach ($name in $ForbiddenFileNames) {
        Get-ChildItem $RepoRoot -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $name } |
            ForEach-Object { $hits.Add((Convert-ToRepoRelativePath $_.FullName)) }
    }

    foreach ($pattern in $ForbiddenFilePatterns) {
        Get-ChildItem $RepoRoot -Recurse -Force -File -Filter $pattern -ErrorAction SilentlyContinue |
            ForEach-Object { $hits.Add((Convert-ToRepoRelativePath $_.FullName)) }
    }

    return $hits | Sort-Object -Unique
}

if (Test-HasGitMetadata) {
    Write-Host "Mode: Git working tree tracked-artifact guard"

    $hits = Find-TrackedForbiddenArtifacts

    if ($hits.Count -gt 0) {
        Write-Host ""
        Write-Host "FAIL: forbidden generated/private/build artifacts are tracked:"
        $hits | ForEach-Object { Write-Host "  $_" }
        exit 1
    }

    Write-Host "PASS: no tracked Rust/build artifacts found"
    exit 0
}

Write-Host "Mode: source snapshot filesystem fallback"
Write-Host "No .git metadata was detected."
Write-Host "Tracked-artifact checks are unavailable in release ZIP/source snapshot mode."

$fsHits = Find-FilesystemForbiddenArtifacts

if ($fsHits.Count -eq 0) {
    Write-Host "PASS: no forbidden generated/private/build artifacts found in filesystem fallback scan"
    exit 0
}

Write-Host ""
Write-Host "Filesystem fallback found generated/private/build artifacts:"
$fsHits | ForEach-Object { Write-Host "  $_" }

if ($StrictFilesystem) {
    Write-Host ""
    Write-Host "FAIL: StrictFilesystem was requested and filesystem artifacts were found"
    exit 1
}

Write-Host ""
Write-Host "PASS: source snapshot fallback completed in non-strict mode"
Write-Host "Note: tests may generate target/, OpenMLS dev state, temp DBs, and executables after validation."
Write-Host "These findings are informational unless StrictFilesystem is used."
exit 0
