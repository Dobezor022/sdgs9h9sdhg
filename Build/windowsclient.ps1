[CmdletBinding()]
param([switch]$SkipTests)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# FedMes 3.0 production builds must not reuse stale C# output after a source or design hotfix.
$cleanProjects = @(
    (Join-Path $root 'desktop\FedMes.Desktop.Core'),
    (Join-Path $root 'desktop\FedMes.Desktop'),
    (Join-Path $root 'desktop\FedMes.Desktop.Tests')
)
foreach ($projectDir in $cleanProjects) {
    foreach ($name in @('bin', 'obj')) {
        $candidate = Join-Path $projectDir $name
        if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Recurse -Force
        }
    }
}
$builder = Join-Path $PSScriptRoot 'fedmes-build.exe'
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) { throw "Не найден $builder" }
$argsList = @('--root', $root)
if ($SkipTests) { $argsList += '--skip-tests' }
$argsList += 'windowsclient'
& $builder @argsList
if ($LASTEXITCODE -ne 0) { throw "Сборка Windows-клиента завершилась с кодом $LASTEXITCODE" }
