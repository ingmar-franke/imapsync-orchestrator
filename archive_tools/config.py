"""Configuration for offline and online archive tools.

Environment variables must be set explicitly for live access; no secrets are
stored here. For security, this module does not parse local .env files.
"""
from __future__ import annotations
import os
from pathlib import Path

MIGRATION_ROOT = Path(os.environ.get('IMAP_MIGRATION_ROOT', str(Path.home() / '.local/share/imap-archive/migration'))).expanduser()
AUDIT_ROOT = Path(os.environ.get('IMAP_AUDIT_ROOT', str(Path.home() / '.local/share/imap-archive/audit'))).expanduser()
SOURCE_HOST = os.environ.get('IMAP_SOURCE_HOST', '')
TARGET_HOST = os.environ.get('IMAP_TARGET_HOST', '')
SOURCE_USER = os.environ.get('IMAP_SOURCE_USER', '')
TARGET_USER = os.environ.get('IMAP_TARGET_USER', '')
# Source and target folder names may differ. Legacy single-name settings remain fallback.
SOURCE_INBOX_FOLDER = os.environ.get('IMAP_SOURCE_INBOX_FOLDER', os.environ.get('IMAP_INBOX_FOLDER', 'INBOX'))
TARGET_INBOX_FOLDER = os.environ.get('IMAP_TARGET_INBOX_FOLDER', os.environ.get('IMAP_INBOX_FOLDER', 'INBOX'))
SOURCE_SENT_FOLDER = os.environ.get('IMAP_SOURCE_SENT_FOLDER', os.environ.get('IMAP_SENT_FOLDER', 'Sent'))
TARGET_SENT_FOLDER = os.environ.get('IMAP_TARGET_SENT_FOLDER', os.environ.get('IMAP_SENT_FOLDER', 'Sent'))
INBOX_FOLDER = SOURCE_INBOX_FOLDER  # compatibility for source-only analyzers
SENT_FOLDER = SOURCE_SENT_FOLDER

def folder(side: str, kind: str) -> str:
    if side not in ('source', 'target') or kind not in ('inbox', 'sent'):
        raise ValueError('Unsupported IMAP folder side/kind')
    return {('source', 'inbox'): SOURCE_INBOX_FOLDER,
            ('target', 'inbox'): TARGET_INBOX_FOLDER,
            ('source', 'sent'): SOURCE_SENT_FOLDER,
            ('target', 'sent'): TARGET_SENT_FOLDER}[(side, kind)]

def quote_imap_folder(name: str) -> str:
    if not name or any(x in name for x in ('\\', '"', '\r', '\n', '\x00')):
        raise ValueError('Unsafe IMAP folder name (quote, backslash or control character)')
    return '"' + name + '"'

OAUTH_HELPER = Path(os.environ.get('IMAP_OAUTH_HELPER', str(Path.home() / '.config/imap-archive/oauth_refresh.py'))).expanduser()
OAUTH_WRAPPER = Path(os.environ.get('IMAP_OAUTH_WRAPPER', str(Path.home() / '.config/imap-archive/orchestrator.py'))).expanduser()
OAUTH_TOKEN = Path(os.environ.get('IMAP_OAUTH_TOKEN', str(Path.home() / '.config/imap-archive/access_token.txt'))).expanduser()

def require_online() -> None:
    """Refuse network operations if account identity is not explicitly configured."""
    missing = [name for name in ('IMAP_SOURCE_HOST', 'IMAP_TARGET_HOST', 'IMAP_SOURCE_USER', 'IMAP_TARGET_USER')
               if not os.environ.get(name)]
    if missing:
        raise RuntimeError('Live IMAP operation requires explicit settings: ' + ', '.join(missing))
    for kind in ('inbox', 'sent'):
        for side in ('source', 'target'):
            quote_imap_folder(folder(side, kind))
