#!/usr/bin/env python3
from __future__ import annotations
import json, re, sqlite3, sys, tempfile, os, tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / 'server'
SRC = SERVER / 'src'
LEGACY = ROOT / 'legacy-reference' / 'server-go-2.0.0'


def fail(msg: str) -> None:
    raise SystemExit('FAIL: ' + msg)


def normalize_path(path: str) -> str:
    path = re.sub(r'\{[^}/]+\}', '{}', path)
    path = re.sub(r':[^/]+', '{}', path)
    return path


def rust_lexical_balance(text: str, name: str) -> None:
    pairs = {')': '(', ']': '[', '}': '{'}
    stack: list[tuple[str, int]] = []
    i = 0; line = 1; state = 'code'; raw_hashes = 0
    while i < len(text):
        c = text[i]; n = text[i+1] if i+1 < len(text) else ''
        if c == '\n': line += 1
        if state == 'line_comment':
            if c == '\n': state = 'code'
            i += 1; continue
        if state == 'block_comment':
            if c == '*' and n == '/': state = 'code'; i += 2; continue
            i += 1; continue
        if state == 'string':
            if c == '\\': i += 2; continue
            if c == '"': state = 'code'
            i += 1; continue
        if state == 'char':
            if c == '\\': i += 2; continue
            if c == "'": state = 'code'
            i += 1; continue
        if state == 'raw':
            if c == '"' and text.startswith('#' * raw_hashes, i+1):
                i += 1 + raw_hashes; state = 'code'; continue
            i += 1; continue
        if c == '/' and n == '/': state = 'line_comment'; i += 2; continue
        if c == '/' and n == '*': state = 'block_comment'; i += 2; continue
        # Rust raw strings r"...", r#"..."#, br#"..."#
        if c in ('r','b'):
            start = i
            j = i + 1
            if c == 'b' and j < len(text) and text[j] == 'r': j += 1
            if j <= len(text) and (text[start:j].endswith('r')):
                h = 0
                while j < len(text) and text[j] == '#': h += 1; j += 1
                if j < len(text) and text[j] == '"':
                    state='raw'; raw_hashes=h; i=j+1; continue
        if c == '"': state='string'; i += 1; continue
        # Lifetime apostrophes are not char literals; only treat quote as char when a plausible closing quote exists nearby.
        if c == "'":
            j=i+1
            if j < len(text) and text[j] == '\\': j += 2
            else: j += 1
            if j < len(text) and text[j] == "'": state='char'
            i += 1; continue
        if c in '([{': stack.append((c,line))
        elif c in ')]}':
            if not stack or stack[-1][0] != pairs[c]: fail(f'{name}:{line}: unbalanced {c}')
            stack.pop()
        i += 1
    if state in ('block_comment','string','raw'): fail(f'{name}: unterminated {state}')
    if stack: fail(f'{name}: unclosed {stack[-1][0]} from line {stack[-1][1]}')


# Cargo metadata is deterministic at top level: no git/path dependencies in production server.
cargo = tomllib.loads((SERVER/'Cargo.toml').read_text('utf-8'))
if cargo['package']['version'] != '3.0.0': fail('Cargo package version is not 3.0.0')
if cargo['package'].get('rust-version') != '1.85': fail('unexpected rust-version')
for name, spec in cargo.get('dependencies', {}).items():
    if isinstance(spec, dict) and ('git' in spec or 'path' in spec): fail(f'production dependency {name} uses git/path')
    version = spec if isinstance(spec, str) else spec.get('version') if isinstance(spec, dict) else None
    if not isinstance(version, str) or not version.startswith('='): fail(f'dependency {name} is not exact-pinned: {version!r}')

# Source sanity: balance syntax delimiters and reject explicit panic shortcuts in production runtime.
for p in sorted(SRC.rglob('*.rs')):
    text = p.read_text('utf-8')
    rust_lexical_balance(text, str(p.relative_to(ROOT)))
    for token in ('unwrap()', '.unwrap(', '.expect(', 'panic!(', 'todo!(', 'unimplemented!('):
        if token in text: fail(f'{p.relative_to(ROOT)} contains production panic shortcut {token}')
    if re.search(r'\bunsafe\s*\{', text): fail(f'{p.relative_to(ROOT)} contains unsafe block')

# Required binaries and migrations.
for binary in ('fedmes-server','fedmes-qr','fedmes-update-server','fedmes-maintainer'):
    if not (SRC/'bin'/f'{binary}.rs').is_file(): fail(f'missing src/bin/{binary}.rs')

migrations = sorted((SERVER/'migrations').glob('*.sql'))
if len(migrations) != 14: fail(f'expected 14 migrations, got {len(migrations)}')
fd, db_path = tempfile.mkstemp(prefix='fedmes-validate-', suffix='.sqlite3'); os.close(fd)
conn = sqlite3.connect(db_path)
try:
    conn.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT")
    for version, p in enumerate(migrations, 1):
        conn.executescript(p.read_text('utf-8'))
        conn.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
    conn.commit()
    scalar = lambda q: conn.execute(q).fetchone()[0]
    if scalar('SELECT MAX(version) FROM schema_migrations') != 14: fail('schema max != 14')
    if scalar('SELECT COUNT(*) FROM family_users') != 5: fail('family user seed != 5')
    if scalar('SELECT COUNT(*) FROM chats') != 16: fail('default chat topology != 16')
    for user in ('grisha','papa','mama','yura','vasya'):
        if scalar(f"SELECT COUNT(*) FROM chat_members WHERE username='{user}'") != 6: fail(f'{user} membership != 6')
finally:
    conn.close(); os.unlink(db_path)

# HTTP route coverage: every route exposed by the Go 2.0.0 reference must still exist in Rust.
go_routes: set[tuple[str,str]] = set()
for p in LEGACY.rglob('*.go'):
    text = p.read_text('utf-8', errors='ignore')
    # Go 1.22 ServeMux method-aware patterns appear only as Handle/HandleFunc arguments.
    # Requiring the call prefix avoids misclassifying SQL raw strings such as `DELETE FROM ...` as HTTP routes.
    route_re = r'(?:\.?(?:Handle|HandleFunc))\(\s*["`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^"`]+)["`]'
    for method, path in re.findall(route_re, text):
        go_routes.add((method, normalize_path(path.strip())))

rust_text=(SRC/'server.rs').read_text('utf-8')
rust_routes: set[tuple[str,str]] = set()
for m in re.finditer(r'\.route\("([^"]+)"\s*,\s*([^\n]+)\)', rust_text):
    path=normalize_path(m.group(1)); expr=m.group(2)
    for meth in re.findall(r'\b(get|post|put|delete|patch)\s*\(', expr, flags=re.I):
        rust_routes.add((meth.upper(), path))
missing=sorted(go_routes-rust_routes)
if missing: fail('Rust route coverage missing: '+', '.join(f'{m} {p}' for m,p in missing))

# Transition invariants.
server_rs=rust_text
for route in ('/api/v1/provisioning/bootstrap-commit','/api/v3/chats/:chat/crypto-sequence/lease','/health/ready'):
    if route not in server_rs: fail(f'missing 3.0 route {route}')
if 'opaque_rust_provider_required' not in (SRC/'legacy.rs').read_text('utf-8'): fail('OPAQUE must fail closed')
if '"opaque_available":false' not in (SRC/'security.rs').read_text('utf-8'): fail('OPAQUE availability must be advertised false')

print(f'Rust source validation: PASS; Go routes={len(go_routes)}, Rust routes={len(rust_routes)}, migrations=14, topology=16/6')
