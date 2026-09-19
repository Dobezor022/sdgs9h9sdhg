[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CommandLineToolsZip,

    [string]$SdkRoot = 'C:\Android\Sdk',
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command java.exe -ErrorAction SilentlyContinue)) {
    throw 'Java 21 не найдена в PATH. Установите JDK 21 и повторите команду.'
}

$javaVersion = (& java.exe -version 2>&1 | Select-Object -First 1) -join ''
if ($javaVersion -notmatch '"21(?:\.|\")') {
    throw "Нужна JDK 21. Обнаружено: $javaVersion"
}

$SdkRoot = [System.IO.Path]::GetFullPath($SdkRoot)
$temporary = Join-Path $env:TEMP ('fedmes-android-tools-' + [Guid]::NewGuid().ToString('N'))
$latest = Join-Path $SdkRoot 'cmdline-tools\latest'

try {
    New-Item -ItemType Directory -Path $temporary -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $latest) -Force | Out-Null
    Expand-Archive -LiteralPath $CommandLineToolsZip -DestinationPath $temporary -Force

    $sdkManager = Get-ChildItem -LiteralPath $temporary -Filter sdkmanager.bat -File -Recurse |
        Select-Object -First 1
    if (-not $sdkManager) {
        throw 'В ZIP не найден sdkmanager.bat. Используйте официальный архив Android command-line tools.'
    }

    $toolRoot = Split-Path -Parent (Split-Path -Parent $sdkManager.FullName)
    if (Test-Path -LiteralPath $latest) {
        $backup = "$latest.previous-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Move-Item -LiteralPath $latest -Destination $backup
    }
    New-Item -ItemType Directory -Path $latest -Force | Out-Null
    Get-ChildItem -LiteralPath $toolRoot -Force | ForEach-Object {
        Move-Item -LiteralPath $_.FullName -Destination $latest -Force
    }

    $sdkManagerPath = Join-Path $latest 'bin\sdkmanager.bat'
    if (-not (Test-Path -LiteralPath $sdkManagerPath -PathType Leaf)) {
        throw "После установки не найден $sdkManagerPath"
    }

    $env:ANDROID_SDK_ROOT = $SdkRoot
    $env:ANDROID_HOME = $SdkRoot
    $env:Path = "$SdkRoot\platform-tools;$latest\bin;$env:Path"

    $accept = ((1..250 | ForEach-Object { 'y' }) -join [Environment]::NewLine)
    $accept | & $sdkManagerPath --sdk_root=$SdkRoot --licenses | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "sdkmanager --licenses завершился с кодом $LASTEXITCODE"
    }

    & $sdkManagerPath --sdk_root=$SdkRoot `
        'platform-tools' `
        'platforms;android-37' `
        'build-tools;37.0.0'
    if ($LASTEXITCODE -ne 0) {
        throw "Установка Android SDK завершилась с кодом $LASTEXITCODE"
    }

    [Environment]::SetEnvironmentVariable('ANDROID_SDK_ROOT', $SdkRoot, 'User')
    [Environment]::SetEnvironmentVariable('ANDROID_HOME', $SdkRoot, 'User')

    $localProperties = Join-Path $ProjectRoot 'android\local.properties'
    $canonicalSdk = [System.IO.Path]::GetFullPath($SdkRoot).TrimEnd('\', '/')
    $encoded = $canonicalSdk.Replace('\', '/').Replace(':', '\:')
    [System.IO.File]::WriteAllText(
        $localProperties,
        "sdk.dir=$encoded`n",
        (New-Object System.Text.UTF8Encoding($false))
    )

    Write-Host ''
    Write-Host "Android SDK установлен: $SdkRoot"
    Write-Host "Создан: $localProperties"
    Write-Host 'Закройте и заново откройте PowerShell, чтобы применились пользовательские переменные.'
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
