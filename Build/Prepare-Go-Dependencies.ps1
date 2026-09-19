param(
    [string]$ProjectRoot = "C:\Users\STUDIO-PC\Pictures\androidconsole"
)

$ErrorActionPreference = "Stop"
$cryptoRoot = Join-Path $ProjectRoot "crypto-core"
$goMod = Join-Path $cryptoRoot "go.mod"
if (-not (Test-Path -LiteralPath $goMod -PathType Leaf)) {
    throw "crypto-core/go.mod was not found: $goMod"
}

Push-Location $cryptoRoot
try {
    $previousGoFlags = $env:GOFLAGS
    $env:GOFLAGS = "-mod=mod"

    $mobileVersion = "v0.0.0-20260520154334-0e4426e1883d"
    $gobindTool = "golang.org/x/mobile/cmd/gobind"
    $patchedKsf = Join-Path $cryptoRoot "third_party\ksf\go.mod"
    if (-not (Test-Path -LiteralPath $patchedKsf -PathType Leaf)) {
        throw "FedMes patched github.com/bytemare/ksf module was not found: $patchedKsf"
    }

    & go mod edit "-replace=github.com/bytemare/ksf=./third_party/ksf"
    if ($LASTEXITCODE -ne 0) {
        throw "go mod edit for patched github.com/bytemare/ksf failed with exit code $LASTEXITCODE"
    }
    & go mod edit "-require=golang.org/x/mobile@$mobileVersion"
    if ($LASTEXITCODE -ne 0) {
        throw "go mod edit for golang.org/x/mobile failed with exit code $LASTEXITCODE"
    }
    & go mod edit "-tool=$gobindTool"
    if ($LASTEXITCODE -ne 0) {
        throw "go mod edit for gobind tool failed with exit code $LASTEXITCODE"
    }

    & go mod tidy
    if ($LASTEXITCODE -ne 0) {
        throw "go mod tidy failed with exit code $LASTEXITCODE"
    }
    & go mod verify
    if ($LASTEXITCODE -ne 0) {
        throw "go mod verify failed with exit code $LASTEXITCODE"
    }
}
finally {
    $env:GOFLAGS = $previousGoFlags
    Pop-Location
}

Write-Host "FedMes crypto-core dependencies are ready."
