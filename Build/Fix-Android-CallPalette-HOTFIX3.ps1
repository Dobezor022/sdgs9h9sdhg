param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)
$ErrorActionPreference = 'Stop'
$file = Join-Path $ProjectRoot 'android\app\src\main\java\com\fedmes\app\calling\FedMesCallScreen.kt'
if (-not (Test-Path $file)) { throw "FedMesCallScreen.kt not found: $file" }
$text = [IO.File]::ReadAllText($file)
$old = 'Text(callStatus(state), color = palette.textSecondary, fontSize = 14.sp)'
$new = 'Text(callStatus(state), color = palette.muted, fontSize = 14.sp)'
$count = ([regex]::Matches($text, [regex]::Escape($old))).Count
if ($count -eq 1) {
    [IO.File]::WriteAllText($file, $text.Replace($old, $new), [Text.UTF8Encoding]::new($false))
    Write-Host 'FedMesCallScreen.kt: HOTFIX3 applied.' -ForegroundColor Green
} elseif ($text.Contains($new) -and -not $text.Contains('palette.textSecondary')) {
    Write-Host 'FedMesCallScreen.kt: HOTFIX3 already applied.' -ForegroundColor Green
} else {
    throw "Unexpected source state. Expected exactly one legacy textSecondary call; found $count."
}
if ([IO.File]::ReadAllText($file).Contains('palette.textSecondary')) {
    throw 'Verification failed: palette.textSecondary still exists.'
}
Write-Host 'Run next: .\Build\fedmes-build.exe --root . android' -ForegroundColor Cyan
