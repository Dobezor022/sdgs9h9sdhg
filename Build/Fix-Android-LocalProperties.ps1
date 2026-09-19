[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$SdkRoot = $(
        if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME }
        else { 'C:\Android\SDK' }
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SdkRoot = [System.IO.Path]::GetFullPath($SdkRoot).TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $SdkRoot -PathType Container)) {
    throw "Android SDK не найден: $SdkRoot"
}

$localProperties = Join-Path $ProjectRoot 'android\local.properties'
$parent = Split-Path -Parent $localProperties
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Android-проект не найден: $parent"
}

$encoded = $SdkRoot.Replace('\', '/').Replace(':', '\:')
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($localProperties, "sdk.dir=$encoded`n", $utf8NoBom)

$raw = [System.IO.File]::ReadAllBytes($localProperties)
if ($raw -contains 13) {
    throw 'local.properties содержит CR (0x0D), исправление не применено корректно.'
}

Write-Host "Исправлен: $localProperties"
Get-Content -LiteralPath $localProperties
