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
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-brightgreen?style=flat-square)](#security)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## What is YukiCrypt?

YukiCrypt is a personal encrypted file vault — it stores any files you want (documents, photos, videos, wallets, anything) inside a single encrypted `.ykc` file that looks like random data to anyone without your password.

- **No drivers** — works on any Windows machine, no installation needed
- **No admin rights** — runs as a normal user
- **No cloud** — your data stays on your machine or USB drive
- **One file** — your entire vault is a single `.ykc` file, easy to back up or move

---

## Screenshots

| Dark Theme | Light Theme |
|---|---|
| *(dark terminal aesthetic)* | *(clean light mode)* |

---

## Quick Start

```bash
# Install dependencies
pip install PyQt6 cryptography

# Optional but recommended — stronger key derivation
pip install argon2-cffi

# Run
python app.py
```

That's it. No drivers. No VeraCrypt. No Microsoft permissions.

---

## Features

### File Management
- Browse files in a folder tree — works like Windows Explorer
- Drag & drop files and folders directly into the vault
- Double-click any file to open it in the right app (Word, VLC, etc.)
- Files are automatically re-encrypted when you save and close them
- Full subfolder support — preserves original folder structure

### Security
- **AES-256-GCM** encryption — same algorithm used by Signal and WhatsApp
- **Argon2id** key derivation — 64MB RAM cost, defeats GPU brute-force attacks
- **Filenames encrypted** — attacker can't see what files you have, only that a vault exists
- **Authenticated encryption** — any tampering or corruption is instantly detected
- **Temp files wiped** — 3-pass random overwrite before deletion
- **Key zeroed on close** — encryption key cleared from memory when vault locks

### Vault Protection
- **Integrity check** — scans every file's authentication tag, detects bit rot and tampering
- **Atomic backup** — crash-safe backup using SQLite's built-in backup API
- **Emergency recovery** — extracts all readable files even from a partially damaged vault
- **Disk space check** — warns before importing if disk is nearly full

### UI
- Dark and light themes, switchable instantly
- Progress bar for all long operations (import, delete, backup, check)
- Non-blocking — all heavy operations run in background threads
- Keyboard shortcut: Enter to unlock

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

The vault file contains no plaintext — filenames, file contents, and folder structure are all encrypted. An attacker who steals the file sees only random bytes.

---

## Security Properties

| Property | Detail |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id — 64MB RAM, 3 passes, 4 threads |
| Nonce | 96-bit cryptographically random, unique per file per write |
| Path binding | File path used as GCM additional data — blobs can't be swapped |
| Filenames | Also encrypted — vault reveals nothing about contents |
| Temp files | 3-pass random overwrite before deletion |
| Key in memory | Zeroed with `ctypes.memset` on vault lock/close |
| Wrong password | Detected instantly via encrypted verification blob |
| Tamper detection | GCM authentication tag catches any modification |
| Crash safety | SQLite WAL mode + `PRAGMA synchronous=FULL` |
| Duplicate writes | Old encrypted blob securely wiped before replacing |

### Threat Model

✅ **Protected against:**
- Stolen laptop or hard drive
- Cloud storage provider snooping
- Casual attackers and nosy people
- Bit rot and silent data corruption

⚠️ **Partial protection:**
- Live memory forensics (key is wiped on close, but Python GC is not fully controllable)
- Sophisticated targeted malware on your running machine

❌ **Not designed for:**
- Nation-state adversaries
- Scenarios requiring plausible deniability (use VeraCrypt for that)

---

## File Structure

```
yukicrypt/
├── app.py       — GUI application (PyQt6)
├── vault.py     — Encryption engine (AES-256-GCM, Argon2id, SQLite)
└── README.md
```

---

## Building a Standalone Exe

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name YukiCrypt app.py
```

Output: `dist/YukiCrypt.exe` — runs on any Windows machine, no Python needed.

---

## Vault File Format

| Layer | Detail |
|---|---|
| Container | SQLite database (`.ykc`) |
| Meta table | Salt, KDF info, encrypted verification blob |
| Files table | `enc_path`, `path_nonce`, `enc_data`, `data_nonce`, `size`, `modified` |
| Path index | In-memory dict for O(1) file lookup (rebuilt on open) |

All sensitive columns (`enc_path`, `enc_data`) are AES-256-GCM encrypted blobs. The SQLite structure itself reveals only the number of files stored, nothing else.

---

## Dependencies

| Package | Purpose | Required |
|---|---|---|
| `PyQt6` | GUI framework | ✅ Yes |
| `cryptography` | AES-256-GCM, PBKDF2 | ✅ Yes |
| `argon2-cffi` | Argon2id key derivation | ⭐ Recommended |

Install:
```bash
pip install PyQt6 cryptography argon2-cffi
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with Python · AES-256-GCM · Argon2id
</div>
