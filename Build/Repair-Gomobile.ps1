param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"

function Find-FedMesRoot {
    param([string]$Start)
    if ([string]::IsNullOrWhiteSpace($Start)) {
        return $null
    }
    $current = [IO.Path]::GetFullPath($Start)
    while ($true) {
        $required = @(
            (Join-Path $current "server\go.mod"),
            (Join-Path $current "android\settings.gradle.kts"),
            (Join-Path $current "desktop\FedMes.Desktop.slnx"),
            (Join-Path $current "tools\go.mod")
        )
        $ok = $true
        foreach ($item in $required) {
            if (-not (Test-Path -LiteralPath $item -PathType Leaf)) {
                $ok = $false
                break
            }
        }
        if ($ok) {
            return $current
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            return $null
        }
        $current = $parent
    }
}

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Find-FedMesRoot -Start (Get-Location).Path
}
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $fallback = "C:\Users\STUDIO-PC\Pictures\androidconsole"
    if (Test-Path -LiteralPath (Join-Path $fallback "tools\go.mod") -PathType Leaf) {
        $ProjectRoot = $fallback
    }
}
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    throw "FedMes project root was not found. Pass -ProjectRoot explicitly."
}

$go = Get-Command go -ErrorAction Stop
$goPathRaw = (& $go.Source env GOPATH).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($goPathRaw)) {
    throw "go env GOPATH failed"
}
$goPath = $goPathRaw.Split([IO.Path]::PathSeparator)[0]
$goBin = Join-Path $goPath "bin"
$gomobile = Join-Path $goBin "gomobile.exe"
New-Item -ItemType Directory -Force -Path $goBin | Out-Null

$old = @{
    GOOS = $env:GOOS
    GOARCH = $env:GOARCH
    CGO_ENABLED = $env:CGO_ENABLED
    GOBIN = $env:GOBIN
    GOFLAGS = $env:GOFLAGS
}
try {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $env:GOBIN = $goBin
    $env:GOFLAGS = "-mod=mod"

    $needsInstall = $true
    if (Test-Path -LiteralPath $gomobile -PathType Leaf) {
        try {
            $buildInfoJson = (& $go.Source version -m -json $gomobile 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($buildInfoJson)) {
                $buildInfo = $buildInfoJson | ConvertFrom-Json
                $goos = ($buildInfo.Settings | Where-Object { $_.Key -eq "GOOS" } | Select-Object -First 1).Value
                $goarch = ($buildInfo.Settings | Where-Object { $_.Key -eq "GOARCH" } | Select-Object -First 1).Value
                if ($goos -eq "windows" -and $goarch -eq "amd64") {
                    $needsInstall = $false
                }
            }
        }
        catch {
            $needsInstall = $true
        }
    }

    if ($needsInstall) {
        if (Test-Path -LiteralPath $gomobile -PathType Leaf) {
            Remove-Item -LiteralPath $gomobile -Force
        }
        & $go.Source install "golang.org/x/mobile/cmd/gomobile@v0.0.0-20260520154334-0e4426e1883d"
        if ($LASTEXITCODE -ne 0) {
            throw "go install gomobile failed with exit code $LASTEXITCODE"
        }
    }

    if (-not (Test-Path -LiteralPath $gomobile -PathType Leaf)) {
        throw "gomobile.exe was not created: $gomobile"
    }
    $buildInfoJson = (& $go.Source version -m -json $gomobile 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($buildInfoJson)) {
        throw "gomobile build-info verification failed: $buildInfoJson"
    }
    $buildInfo = $buildInfoJson | ConvertFrom-Json
    $goos = ($buildInfo.Settings | Where-Object { $_.Key -eq "GOOS" } | Select-Object -First 1).Value
    $goarch = ($buildInfo.Settings | Where-Object { $_.Key -eq "GOARCH" } | Select-Object -First 1).Value
    if ($goos -ne "windows" -or $goarch -ne "amd64") {
        throw "gomobile host verification failed: expected windows/amd64, got $goos/$goarch"
    }

    Write-Host "gomobile ready: $gomobile"
    Write-Host "Target: $goos/$goarch; Go: $($buildInfo.GoVersion)"
    Write-Host "Project: $ProjectRoot"
}
finally {
    $env:GOOS = $old.GOOS
    $env:GOARCH = $old.GOARCH
    $env:CGO_ENABLED = $old.CGO_ENABLED
    $env:GOBIN = $old.GOBIN
    $env:GOFLAGS = $old.GOFLAGS
}
