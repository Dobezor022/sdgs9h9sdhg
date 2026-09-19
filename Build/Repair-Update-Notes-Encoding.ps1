[CmdletBinding()]
param(
    [string]$Server = '78.17.107.104',
    [string]$User = 'root'
)

$ErrorActionPreference = 'Stop'
$target = "${User}@${Server}"

# The remote payload is ASCII-only. Russian text is transferred as Base64-encoded UTF-8,
# so Windows PowerShell 5.1, cmd.exe code pages, and OpenSSH cannot corrupt it.
$remote = @'
set -Eeuo pipefail
MANIFEST=/var/lib/fedmes/updates/releases.json
NORMAL_B64='RmVkTWVzIDEuMC40IGhvdGZpeCAxMDAwNjog0YHQuNGB0YLQtdC80L3QvtC1INC80LXQvdGOIEFuZHJvaWQvR29vZ2xlINC/0YDQuCDQstGL0LTQtdC70LXQvdC40Lgg0YLQtdC60YHRgtCwINC+0YLQutC70Y7Rh9C10L3Qvjsg0LjRgdC/0L7Qu9GM0LfRg9C10YLRgdGPINGC0L7Qu9GM0LrQviDQv9Cw0L3QtdC70YwgRmVkTWVzLg=='
HUAWEI_B64='RmVkTWVzIDEuMC40IGhvdGZpeCAxMDAwNjog0YHQuNGB0YLQtdC80L3QvtC1INC80LXQvdGOIEFuZHJvaWQvSHVhd2VpINC/0YDQuCDQstGL0LTQtdC70LXQvdC40Lgg0YLQtdC60YHRgtCwINC+0YLQutC70Y7Rh9C10L3Qvjsg0LjRgdC/0L7Qu9GM0LfRg9C10YLRgdGPINGC0L7Qu9GM0LrQviDQv9Cw0L3QtdC70YwgRmVkTWVzLg=='
WINDOWS_B64='RmVkTWVzIDEuMC40OiDQv9GA0L7QutGA0YPRgtC60LAg0YfQsNGC0LAg0LLQvdC40Lcg0L/RgNC4INCy0LLQvtC00LUsINC80YPQu9GM0YLQuNCy0YvQsdC+0YAg0L7QsdGK0LXQutGC0L7Qsiwg0LLRi9GA0LXQt9Cw0YLRjCwg0LrQvtC/0LjRgNC+0LLQsNGC0YwsINGG0LjRgtC40YDQvtCy0LDRgtGMINC4INGE0L7RgNC80LDRgtC40YDQvtCy0LDQvdC40LUg0YLQtdC60YHRgtCwLiBXaW5kb3dzIHg2NC4='
export MANIFEST NORMAL_B64 HUAWEI_B64 WINDOWS_B64
python3 - <<'PYTHON_EOF'
import base64
import json
import os
import pathlib
import tempfile

manifest_path = pathlib.Path(os.environ['MANIFEST'])
with manifest_path.open('r', encoding='utf-8') as handle:
    manifest = json.load(handle)

def decode(name: str) -> str:
    return base64.b64decode(os.environ[name], validate=True).decode('utf-8')

releases = manifest.setdefault('releases', {})
if 'android-normal' in releases:
    releases['android-normal']['notes'] = decode('NORMAL_B64')
if 'android-huawei' in releases:
    releases['android-huawei']['notes'] = decode('HUAWEI_B64')
if 'windows-x64' in releases:
    releases['windows-x64']['notes'] = decode('WINDOWS_B64')

fd, temporary = tempfile.mkstemp(prefix='releases-', suffix='.json', dir=str(manifest_path.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o640)
    os.replace(temporary, manifest_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYTHON_EOF
chown root:fedmes "$MANIFEST"
chmod 0640 "$MANIFEST"
systemctl restart fedmes-update.service
for i in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8010/health; then
        echo
        break
    fi
    if [ "$i" -eq 30 ]; then
        systemctl status fedmes-update.service --no-pager -l
        journalctl -u fedmes-update.service -n 100 --no-pager
        exit 1
    fi
    sleep 1
done
python3 - <<'PYTHON_EOF'
import json
p='/var/lib/fedmes/updates/releases.json'
with open(p, encoding='utf-8') as f:
    m=json.load(f)
for platform in ('android-normal','android-huawei','windows-x64'):
    r=m.get('releases',{}).get(platform)
    if r:
        print(platform + ': ' + r.get('notes',''))
PYTHON_EOF
'@

& ssh $target $remote
if ($LASTEXITCODE -ne 0) {
    throw 'Не удалось исправить кодировку описания обновления.'
}
Write-Host 'Кодировка описания обновления исправлена.'
