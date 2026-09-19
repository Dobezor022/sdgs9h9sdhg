$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host '[1/4] Project version'
& (Join-Path $Root 'Build\fedmes-build.exe') --version
Write-Host '[2/4] security2 tests'
Push-Location (Join-Path $Root 'security2')
try { $env:GOTOOLCHAIN='local'; go test ./... } finally { Pop-Location }
Write-Host '[3/4] tools tests'
Push-Location (Join-Path $Root 'tools')
try { $env:GOTOOLCHAIN='local'; go test ./... } finally { Pop-Location }
Write-Host '[4/4] Full target builds'
Write-Host 'Run: Build\all.ps1 after installing the pinned Go 1.25+, .NET 10 SDK, JDK 21 and Android SDK.'
