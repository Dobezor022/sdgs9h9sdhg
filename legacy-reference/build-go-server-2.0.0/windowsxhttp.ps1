[CmdletBinding()]
param([switch]$SkipTests)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$builder = Join-Path $PSScriptRoot 'fedmes-build.exe'
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) { throw "Не найден $builder" }
$argsList = @('--root', $root)
if ($SkipTests) { $argsList += '--skip-tests' }
$argsList += 'windowsxhttp'
& $builder @argsList
if ($LASTEXITCODE -ne 0) { throw "Сборка Windows HTTP-сервера завершилась с кодом $LASTEXITCODE" }
