[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [switch]$ConfirmWipe,
    [string]$AndroidPackage = 'com.fedmes.app'
)
$ErrorActionPreference = 'Stop'
if (-not $ConfirmWipe) {
    throw 'This removes local Windows sessions/keys and Android app data. Re-run with -ConfirmWipe.'
}
$targets = @(
    (Join-Path $env:LOCALAPPDATA 'FedMes'),
    (Join-Path $env:APPDATA 'FedMes')
)
foreach ($target in $targets) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Host "Removed $target"
    }
}
$adb = Get-Command adb.exe -ErrorAction SilentlyContinue
if ($null -ne $adb) {
    & $adb.Source shell pm clear $AndroidPackage
}
Write-Host 'Local FedMes data cleared. New QR login is required.'
