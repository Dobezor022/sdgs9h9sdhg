$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Path = Join-Path $Root 'desktop\FedMes.Desktop.Core\Messaging\MessagingApiClient.cs'
if (-not (Test-Path -LiteralPath $Path)) { throw "Missing $Path" }
$text = [IO.File]::ReadAllText($Path)
$old = '    public async Task<IReadOnlyList<CryptoSequenceLeaseItem>> ReserveCryptoSequenceLeaseAsync('
$new = '    internal async Task<IReadOnlyList<CryptoSequenceLeaseItem>> ReserveCryptoSequenceLeaseAsync('
if ($text.Contains($old)) {
    $text = $text.Replace($old, $new)
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
    Write-Host 'MessagingApiClient.cs: HOTFIX4 CS0050 fix applied.' -ForegroundColor Green
} elseif ($text.Contains($new)) {
    Write-Host 'MessagingApiClient.cs: HOTFIX4 already applied.' -ForegroundColor Green
} else {
    throw 'Expected ReserveCryptoSequenceLeaseAsync signature was not found.'
}

$manifest = Join-Path $Root 'RELEASE-MANIFEST.sha256'
if (Test-Path -LiteralPath $manifest) {
    $lines = Get-Content -LiteralPath $manifest
    $relative = './desktop/FedMes.Desktop.Core/Messaging/MessagingApiClient.cs'
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $updated = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match [regex]::Escape($relative) + '$') {
            $lines[$i] = "$hash  $relative"
            $updated = $true
            break
        }
    }
    if ($updated) {
        [IO.File]::WriteAllLines($manifest, $lines, [Text.UTF8Encoding]::new($false))
        Write-Host 'RELEASE-MANIFEST.sha256: MessagingApiClient entry updated.' -ForegroundColor Green
    }
}
