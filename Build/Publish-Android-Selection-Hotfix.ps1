[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Server = '78.17.107.104',
    [string]$User = 'root'
)

$ErrorActionPreference = 'Stop'
$publisher = Join-Path $PSScriptRoot 'Publish-Required-Update-To-Ubuntu.ps1'
if (-not (Test-Path -LiteralPath $publisher -PathType Leaf)) {
    throw "Не найден основной скрипт публикации: $publisher"
}

Write-Warning 'Старое имя скрипта сохранено для совместимости. Публикуется полный выпуск FedMes 1.0.6 build 10015 для Android Normal, Huawei и Windows.'
& $publisher -ProjectRoot $ProjectRoot -Server $Server -User $User
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
