[CmdletBinding()]
param([switch]$SkipTests)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$builder = Join-Path $PSScriptRoot 'fedmes-build.exe'
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) { throw "Не найден $builder" }
$argsList = @('--root', $root)
if ($SkipTests) { $argsList += '--skip-tests' }
$argsList += 'all'
& $builder @argsList
if ($LASTEXITCODE -ne 0) { throw "Полная сборка завершилась с кодом $LASTEXITCODE" }
