param(
    [string]$Server = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

Write-Host "CarbonStackComms local lifecycle test"
Write-Host "Server: $Server"

$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$AliceState = ".test-alice-$RunId\state.json"
$BobState = ".test-bob-$RunId\state.json"
$AliceInvite = "alice-test-$RunId"
$BobInvite = "bob-test-$RunId"
$Message = "hello from cli lifecycle test $RunId"

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

try {
    Run-Comms init --state $AliceState --server $Server
    Run-Comms init --state $BobState --server $Server

    Run-Comms dev-create-invite --state $AliceState --invite $AliceInvite
    Run-Comms dev-create-invite --state $BobState --invite $BobInvite

    Run-Comms claim-invite --state $AliceState --invite $AliceInvite --name "alice-test-$RunId"
    Run-Comms claim-invite --state $BobState --invite $BobInvite --name "bob-test-$RunId"

    Run-Comms register-device --state $AliceState --label "alice-cli-$RunId"
    Run-Comms register-device --state $BobState --label "bob-cli-$RunId"

    $Bob = Get-Content $BobState | ConvertFrom-Json
    $BobDeviceId = $Bob.device_id

    if (-not $BobDeviceId) {
        throw "Bob device_id missing from state"
    }

    $SendOutput = go run .\cmd\comms send --state $AliceState --to-device $BobDeviceId --message $Message
    $SendOutput | ForEach-Object { Write-Host $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "send command failed"
    }

    $InboxOutput = go run .\cmd\comms inbox --state $BobState
    $InboxOutput | ForEach-Object { Write-Host $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "inbox command failed"
    }

    $EnvelopeLine = $InboxOutput | Where-Object { $_ -like "envelope_id:*" } | Select-Object -First 1
    if (-not $EnvelopeLine) {
        throw "no envelope_id found in Bob inbox output"
    }

    $EnvelopeId = ($EnvelopeLine -split ":", 2)[1].Trim()
    if (-not $EnvelopeId) {
        throw "parsed envelope_id is empty"
    }

    Run-Comms ack --state $BobState --envelope $EnvelopeId

    $InboxAfterAck = go run .\cmd\comms inbox --state $BobState
    $InboxAfterAck | ForEach-Object { Write-Host $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "post-ack inbox command failed"
    }

    $EmptyCheck = $InboxAfterAck | Where-Object { $_ -eq "queued_envelopes: 0" }
    if (-not $EmptyCheck) {
        throw "expected queued_envelopes: 0 after ack"
    }

    Write-Host ""
    Write-Host "PASS: local two-client CLI lifecycle validated"
}
finally {
    Remove-Item -Recurse -Force ".test-alice-$RunId" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force ".test-bob-$RunId" -ErrorAction SilentlyContinue
}
