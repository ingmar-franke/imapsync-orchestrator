#!/usr/bin/env python3
"""Fail-closed public release scanner (contains no real user identifiers)."""
from __future__ import annotations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = [
    '.env.archive.example', '.gitignore', '.gitignore.archive',
    'README_ARCHIVE_TOOLS.md',
    *[str(p.relative_to(ROOT)) for p in sorted((ROOT/'archive_tools').glob('*.py'))],
    'scripts/check_archive_release.py', 'tests/archive_tools/test_offline.py',
]
ALLOWED_EMAIL_DOMAINS = {'example.invalid', 'e.invalid'}
ALLOWED_URL_HOSTS = {'example.org', 'example.invalid'}

def inspect(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        raw = path.read_bytes()
        txt = raw.decode('utf-8')
    except UnicodeDecodeError:
        return ['invalid UTF-8 (possibly binary/private data)']
    if b'\x00' in raw:
        errors.append('embedded NUL')
    for m in re.finditer(r'(?i)\b[A-Z0-9._%+\-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b', txt):
        if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
            errors.append('non-example e-mail address')
    for m in re.finditer(r'https?://([A-Za-z0-9.-]+)', txt):
        if m.group(1).lower() not in ALLOWED_URL_HOSTS:
            errors.append('non-example HTTP endpoint')
    patterns = {
        r'(?i)BEGIN\s+(?:RSA|OPENSSH|EC)?\s*PRIVATE KEY': 'private key marker',
        r'(?i)\b(?:client_secret|refresh_token|access_token)\s*[=:]\s*[\"\']?[a-z0-9._-]{30,}': 'credential-like assignment',
        r'\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.': 'JWT-like token',
        r'/(?:Users|home)/[^/\s\"\']+/': 'absolute personal home directory',
        r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)': 'literal IPv4 address',
        r'\b(?:UID|user_id)\s*[:=]\s*[1-9]\d{5,8}\b': 'specific UID/user identifier',
        r'(?i)\b(?:known|historical)\s+\d+\s+(?:duplicate|copy|extra|mehrfach)': 'hard-coded case statistic',
    }
    for pat, reason in patterns.items():
        if re.search(pat, txt):
            errors.append(reason)
    return sorted(set(errors))

def run() -> int:
    errs = []
    for relative in EXPECTED:
        p = ROOT / relative
        if not p.is_file() or p.is_symlink():
            errs.append((relative, 'missing file or symlink'))
            continue
        for reason in inspect(p):
            errs.append((relative, reason))
    # Catch accidental extra files in the release directory; no private artifacts.
    actual = {str(p.relative_to(ROOT)) for p in ROOT.rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    for relative in sorted(actual - set(EXPECTED)):
        errs.append((relative, 'unexpected release file'))
    gitignore = (ROOT/'.gitignore').read_text(encoding='utf-8')
    if not gitignore.lstrip().startswith('# Only explicitly reviewed') or not re.search(r'^\*$', gitignore, re.M):
        errs.append(('.gitignore', 'missing restrictive allowlist'))
    for rel in EXPECTED:
        if rel == '.gitignore':
            continue
        if f'!/{rel}\n' not in gitignore and not (rel.startswith('tests/') and f'!/{rel}\n' in gitignore):
            errs.append(('.gitignore', 'no explicit allowlist entry: '+rel))
    for fn in ('delta_inbox.py','delta_sent.py'):
        if 'cfg.require_online()' not in (ROOT/'archive_tools'/fn).read_text():
            errs.append((fn, 'missing live-operation gate'))
    if errs:
        for relative, reason in errs:
            print('FAIL', relative, reason)
        return 1
    print(f'PASS: {len(EXPECTED)} explicitly allowlisted files; privacy and publication checks OK')
    return 0

if __name__=='__main__':
    sys.exit(run())
