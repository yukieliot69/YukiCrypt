<div align="center">

```
┌─────────────────────────────┐
│                             │
│        ◈ YUKICRYPT          │
│   ENCRYPTED FILE MANAGER    │
│                             │
│   AES-256-GCM · ARGON2ID    │
│   ZERO INSTALLS REQUIRED    │
│                             │
└─────────────────────────────┘
```

# YukiCrypt

**Zero-install encrypted file vault with a full file manager UI.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-green?style=flat-square)](https://pypi.org/project/PyQt6/)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-brightgreen?style=flat-square)](#security-properties)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)](#quick-start)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## What is YukiCrypt?

YukiCrypt is a personal encrypted file vault — store any files you want (documents, photos, videos, wallets, anything) inside a single encrypted `.ykc` file that looks like random data to anyone without your password.

- **No drivers** — works on any machine, no installation needed
- **No admin rights** — runs as a normal user
- **No cloud** — your data stays on your machine or USB drive
- **One file** — your entire vault is a single `.ykc` file, easy to back up or move
- **Cross-platform** — runs on Windows, macOS, and Linux

> ⚠️ The pre-built `.exe` may be flagged by antivirus as a false positive — this is a known issue with all Python apps built with PyInstaller. The full source code is available to review. If you're concerned, run directly from source.

---

## Quick Start

```bash
# Install dependencies
pip install PyQt6 cryptography argon2-cffi

# Run
python app.py
```

That's it. No drivers. No VeraCrypt. No Microsoft permissions.

---

## Features

### File Management
- Browse files in a folder tree — works like Windows Explorer
- Drag & drop files and folders directly into the vault
- Preserves original folder structure including empty folders
- Double-click any file to open it in the right app (Word, VLC, browser, etc.)
- Files automatically re-encrypted when you save and close them
- Export selected files back to disk while preserving folder structure

### Security
- **AES-256-GCM** encryption — same algorithm used by Signal and WhatsApp
- **Argon2id** key derivation — 64MB RAM cost, defeats GPU brute-force attacks
- **Filenames encrypted** — attacker can't see what files you have, only that a vault exists
- **Authenticated encryption** — any tampering or corruption is instantly detected
- **Temp files wiped** — 3-pass random overwrite before deletion
- **Key zeroed on close** — encryption key cleared from memory when vault locks
- **Atomic writes** — crash during save can never leave a file partially written

### Vault Tools
| Button | What it does |
|---|---|
| **✓ CHECK** | Scan every file's AES-GCM tag — detects bit rot and tampering |
| **⊞ BACKUP** | Create a compact encrypted backup (uses `VACUUM INTO` — smaller than original) |
| **▼ COMPACT** | Reclaim space freed by deleted files — shrinks the vault to actual used size |
| **⚕ RECOVER** | Extract all readable files even from a partially damaged vault |

### UI
- Dark and light themes, switchable instantly with the `☀/🌙` button
- Progress bar for all long operations — UI never freezes
- All heavy operations run in background threads
- Disk space check before large imports

---

## How It Works

```
Your password
      │
      ▼
 Argon2id KDF (64MB RAM, 3 passes)   ← Defeats GPU brute-force
      │
      ▼
 AES-256 key
      │
      ▼
 SQLite .ykc vault file
 ├── Every filename   → encrypted with AES-256-GCM + unique nonce
 └── Every file blob  → encrypted with AES-256-GCM + unique nonce
                         └── file path used as AAD (can't swap blobs)
```

The vault file contains no plaintext — filenames, file contents, and folder structure are all encrypted. An attacker who gets the file sees only random bytes.

---

## Security Properties

| Property | Detail |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id — 64MB RAM, 3 passes, 4 threads |
| Fallback KDF | PBKDF2-SHA512, 600,000 iterations |
| Nonce | 96-bit cryptographically random, unique per file per write |
| Path binding | File path used as GCM AAD — encrypted blobs can't be swapped between paths |
| Filenames | Also encrypted — vault reveals nothing about contents |
| Temp files | 3-pass random overwrite before deletion |
| Key in memory | Zeroed with `ctypes.memset` on vault lock/close |
| Wrong password | Detected instantly via encrypted verification blob |
| Tamper detection | GCM authentication tag catches any modification |
| Crash safety | SQLite WAL mode + `PRAGMA synchronous=FULL` + atomic transactions |
| Write safety | DELETE + INSERT wrapped in explicit transaction — no partial writes |
| Compact backup | `VACUUM INTO` — backup never contains deleted file data |

### Threat Model

✅ **Protected against:**
- Stolen laptop or hard drive
- Cloud storage provider snooping
- Casual attackers and nosy people
- Bit rot and silent data corruption (detected by integrity check)

⚠️ **Partial protection:**
- Files are decrypted to a temp folder while open — temp file exists on disk until you close the file
- Live memory forensics (key is wiped on close, but Python GC is not fully controllable)
- Sophisticated targeted malware already running on your machine

❌ **Not designed for:**
- Nation-state adversaries with physical access to your running machine
- Scenarios requiring plausible deniability — use VeraCrypt for that

---

## Vault Size & Compaction

SQLite does not shrink the vault file when files are deleted — it keeps free pages for future use. Use the tools provided to reclaim space:

- **▼ COMPACT** — runs `VACUUM INTO` in place, vault shrinks immediately
- **⊞ BACKUP** — the backup is always compact (only live data is copied)

Example: a 300MB vault after deleting most files → compact brings it down to actual used size.

---

## Building a Standalone Exe

```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed --name YukiCrypt --hidden-import argon2 app.py
```

Output: `dist/YukiCrypt.exe` — runs on any Windows machine with no Python needed.

**macOS / Linux:**
```bash
python -m PyInstaller --onefile --windowed --name YukiCrypt --hidden-import argon2 app.py
```

---

## Vault File Format

| Layer | Detail |
|---|---|
| Container | SQLite database (`.ykc`) |
| Meta table | Salt, KDF info, encrypted verification blob |
| Files table | `enc_path`, `path_nonce`, `enc_data`, `data_nonce`, `size`, `modified` |
| Path index | In-memory dict for O(1) file lookup — rebuilt on open |
| Transactions | All writes atomic — crash cannot corrupt existing files |

All sensitive columns (`enc_path`, `enc_data`) are AES-256-GCM encrypted blobs. The SQLite structure reveals only the number of stored entries — nothing else.

---

## Dependencies

| Package | Purpose | Required |
|---|---|---|
| `PyQt6` | GUI framework | ✅ Yes |
| `cryptography` | AES-256-GCM, PBKDF2 | ✅ Yes |
| `argon2-cffi` | Argon2id key derivation (stronger) | ⭐ Recommended |

```bash
pip install PyQt6 cryptography argon2-cffi
```

---

## File Structure

```
yukicrypt/
├── app.py          — GUI application (PyQt6)
├── vault.py        — Encryption engine (AES-256-GCM, Argon2id, SQLite)
├── requirements.txt
├── LICENSE
└── SECURITY.md     — How to report vulnerabilities
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with Python · AES-256-GCM · Argon2id · SQLite
</div>
