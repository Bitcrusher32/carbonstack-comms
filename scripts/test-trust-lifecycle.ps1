param(
    [string]$Server = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

Write-Host "CarbonStackComms Phase 2A trust lifecycle test"
Write-Host "Server: $Server"

$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$AliceState = ".trust-alice-$RunId\state.json"
$BobState = ".trust-bob-$RunId\state.json"
$AliceInvite = "trust-alice-$RunId"
$BobInvite = "trust-bob-$RunId"
$VerifiedMessage = "phase2a verified send $RunId"
$ReverifiedMessage = "phase2a reverified send $RunId"
$ChangedDevMessage = "phase2a dev override after changed key $RunId"

function Run-Comms {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    Write-Host ""
    Write-Host "> go run .\cmd\comms $($Args -join ' ')"
    go run .\cmd\comms @Args

    if ($LASTEXITCODE -ne 0) {
        throw "command failed: go run .\cmd\comms $($Args -join ' ')"
    }
}

function Run-Comms-Capture {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    Write-Host ""
    Write-Host "> go run .\cmd\comms $($Args -join ' ')"
    $Output = go run .\cmd\comms @Args
    $ExitCode = $LASTEXITCODE

    $Output | ForEach-Object { Write-Host $_ }

    if ($ExitCode -ne 0) {
        throw "command failed: go run .\cmd\comms $($Args -join ' ')"
    }

    return $Output
}

function Run-Comms-AllowFailure {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    Write-Host ""
    Write-Host "> go run .\cmd\comms $($Args -join ' ')"

    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    try {
        $Output = & go run .\cmd\comms @Args 2>&1
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }

    $Output | ForEach-Object { Write-Host $_ }

    return @{
        ExitCode = $ExitCode
        Output = $Output
    }
}

try {
    Run-Comms init --state $AliceState --server $Server
    Run-Comms init --state $BobState --server $Server

    Run-Comms dev-create-invite --state $AliceState --invite $AliceInvite
    Run-Comms dev-create-invite --state $BobState --invite $BobInvite

    Run-Comms claim-invite --state $AliceState --invite $AliceInvite --name "trust-alice-$RunId"
    Run-Comms claim-invite --state $BobState --invite $BobInvite --name "trust-bob-$RunId"

    Run-Comms register-device --state $AliceState --label "trust-alice-device-$RunId"
    Run-Comms register-device --state $BobState --label "trust-bob-device-$RunId"

    $Bob = Get-Content $BobState | ConvertFrom-Json
    $BobDeviceId = $Bob.device_id
    $BobPublicIdentityKey = $Bob.public_identity_key

    if (-not $BobDeviceId) {
        throw "Bob device_id missing from state"
    }

    if (-not $BobPublicIdentityKey) {
        throw "Bob public_identity_key missing from state"
    }

    Run-Comms verify-device --state $AliceState --device $BobDeviceId --public-key $BobPublicIdentityKey --label "trust-bob-device-$RunId"

    $TrustListVerified = Run-Comms-Capture trust-list --state $AliceState
    if (-not ($TrustListVerified | Where-Object { $_ -eq "trust_state: verified" })) {
        throw "trust-list did not show verified state after verification"
    }

    $HistoryOutput = Run-Comms-Capture trust-history --state $AliceState
    if (-not ($HistoryOutput | Where-Object { $_ -like "event_type: device_verified" })) {
        throw "expected device_verified event in trust history"
    }

    Run-Comms send --state $AliceState --to-device $BobDeviceId --message $VerifiedMessage --strict

    $ChangedPublicKey = "fake-new-bob-key-$RunId"
    Run-Comms simulate-key-change --state $AliceState --device $BobDeviceId --new-public-key $ChangedPublicKey

    $TrustListChanged = Run-Comms-Capture trust-list --state $AliceState
    if (-not ($TrustListChanged | Where-Object { $_ -eq "trust_state: changed" })) {
        throw "trust-list did not show changed state after simulated key change"
    }

    $StrictChanged = Run-Comms-AllowFailure send --state $AliceState --to-device $BobDeviceId --message "this should block" --strict

    if ($StrictChanged.ExitCode -eq 0) {
        throw "strict send unexpectedly succeeded after simulated key change"
    }

    if (-not ($StrictChanged.Output | Where-Object { $_ -like "*identity changed*" })) {
        throw "strict changed-device failure did not include identity changed warning"
    }

    Run-Comms send --state $AliceState --to-device $BobDeviceId --message $ChangedDevMessage

    Run-Comms verify-device --state $AliceState --device $BobDeviceId --public-key $ChangedPublicKey --label "trust-bob-device-$RunId"

    $TrustListReverified = Run-Comms-Capture trust-list --state $AliceState
    if (-not ($TrustListReverified | Where-Object { $_ -eq "trust_state: verified" })) {
        throw "trust-list did not show verified state after reverify"
    }

    Run-Comms send --state $AliceState --to-device $BobDeviceId --message $ReverifiedMessage --strict

    Run-Comms revoke-device --state $AliceState --device $BobDeviceId

    $TrustListRevoked = Run-Comms-Capture trust-list --state $AliceState
    if (-not ($TrustListRevoked | Where-Object { $_ -eq "trust_state: revoked" })) {
        throw "trust-list did not show revoked state after revocation"
    }

    $RevokedDev = Run-Comms-AllowFailure send --state $AliceState --to-device $BobDeviceId --message "this should block even in dev"

    if ($RevokedDev.ExitCode -eq 0) {
        throw "dev send unexpectedly succeeded after revocation"
    }

    if (-not ($RevokedDev.Output | Where-Object { $_ -like "*recipient device is revoked*" })) {
        throw "revoked-device failure did not include revoked warning"
    }

    $FinalHistory = Run-Comms-Capture trust-history --state $AliceState

    if (-not ($FinalHistory | Where-Object { $_ -like "event_type: device_verified" })) {
        throw "final trust history missing device_verified"
    }

    if (-not ($FinalHistory | Where-Object { $_ -like "event_type: device_key_changed" })) {
        throw "final trust history missing device_key_changed"
    }

    if (-not ($FinalHistory | Where-Object { $_ -like "event_type: device_revoked" })) {
        throw "final trust history missing device_revoked"
    }

    Write-Host ""
    Write-Host "PASS: Phase 2A trust lifecycle validated"
}
finally {
    Remove-Item -Recurse -Force ".trust-alice-$RunId" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force ".trust-bob-$RunId" -ErrorAction SilentlyContinue
}
