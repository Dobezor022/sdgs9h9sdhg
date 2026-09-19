[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Server = 'fedmes.xuanguang.su',
    [string]$User = 'root'
)

$ErrorActionPreference = 'Stop'
$normal = Join-Path $ProjectRoot 'Build\android\normal\FedMes-normal.apk'
$huawei = Join-Path $ProjectRoot 'Build\android\huawei\harmonous2.0\FedMes-huawei.apk'
$windows = Join-Path $ProjectRoot 'Build\windowsclient\FedMes.Desktop.exe'
$publisher = Join-Path $ProjectRoot 'deploy\publish-release.sh'
foreach ($file in @($normal, $huawei, $windows, $publisher)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Не найден файл: $file" }
}

$target = "${User}@${Server}"
$runnerPath = Join-Path ([IO.Path]::GetTempPath()) ("fedmes-publish-30000-{0}.sh" -f [Guid]::NewGuid().ToString('N'))
$remoteRunner = '/tmp/fedmes-publish-run-30000.sh'
$remotePublisher = '/tmp/fedmes-publish-release-30000.new'
$runner = @'
#!/usr/bin/env bash
set -Eeuo pipefail
cleanup() {
  rm -f /tmp/FedMes-normal-30000.apk /tmp/FedMes-huawei-30000.apk \
    /tmp/FedMes-Windows-30000.exe /tmp/fedmes-publish-release-30000.new \
    /tmp/fedmes-publish-run-30000.sh
}
trap cleanup EXIT
install -o root -g root -m 0755 /tmp/fedmes-publish-release-30000.new /usr/local/sbin/fedmes-publish-release
NOTES="FedMes 3.0.0 build 30000: Rust production backend, event-driven sync, optimistic low-latency messaging, Bridge 1.9 FedUI, realtime/media hardening, secure-session fixes and schema-14 compatibility."
/usr/local/sbin/fedmes-publish-release \
  --normal /tmp/FedMes-normal-30000.apk \
  --huawei /tmp/FedMes-huawei-30000.apk \
  --windows /tmp/FedMes-Windows-30000.exe \
  --version 3.0.0 \
  --version-code 30000 \
  --minimum-code 30000 \
  --notes "$NOTES"
'@
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($runnerPath, $runner.Replace("`r`n", "`n"), $utf8WithoutBom)
try {
    & scp -- $normal "${target}:/tmp/FedMes-normal-30000.apk"
    if ($LASTEXITCODE -ne 0) { throw 'scp Android Normal завершился ошибкой.' }
    & scp -- $huawei "${target}:/tmp/FedMes-huawei-30000.apk"
    if ($LASTEXITCODE -ne 0) { throw 'scp Android Huawei завершился ошибкой.' }
    & scp -- $windows "${target}:/tmp/FedMes-Windows-30000.exe"
    if ($LASTEXITCODE -ne 0) { throw 'scp Windows Client завершился ошибкой.' }
    & scp -- $publisher "${target}:${remotePublisher}"
    if ($LASTEXITCODE -ne 0) { throw 'scp серверного publisher завершился ошибкой.' }
    & scp -- $runnerPath "${target}:${remoteRunner}"
    if ($LASTEXITCODE -ne 0) { throw 'scp сценария публикации завершился ошибкой.' }
    & ssh $target "bash $remoteRunner"
    if ($LASTEXITCODE -ne 0) { throw 'Публикация обновления на Ubuntu завершилась ошибкой.' }
    Write-Host 'FedMes 3.0.0 build 30000 опубликован.'
}
finally { Remove-Item -LiteralPath $runnerPath -Force -ErrorAction SilentlyContinue }
