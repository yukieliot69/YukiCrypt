# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in YukiCrypt, please **do not open a public GitHub issue**.

Instead, report it privately by opening a [GitHub Security Advisory](../../security/advisories/new) or emailing the maintainer directly.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours.

## Scope

The following are considered in-scope vulnerabilities:

- Encryption weaknesses or implementation errors in `vault.py`
- Key derivation issues (Argon2id / PBKDF2 parameters)
- Authenticated encryption bypass
- Temp file insecure deletion
- Memory exposure of encryption keys
- Path traversal in virtual file paths

The following are **out of scope**:

- Attacks requiring physical access to an unlocked running machine
- Weaknesses in underlying Python, PyQt6, or cryptography library
- UI/UX issues that don't affect security

## Cryptographic Choices

| Component | Choice | Rationale |
|---|---|---|
| Encryption | AES-256-GCM | NIST standard, authenticated, widely audited |
| Key derivation (primary) | Argon2id | Winner of Password Hashing Competition, memory-hard |
| Key derivation (fallback) | PBKDF2-SHA512, 600k iterations | NIST recommended when Argon2 unavailable |
| Nonce | 96-bit random | GCM standard, negligible collision probability |
| Nonce reuse protection | Unique nonce per write | Old blob wiped before replacement |
| AAD | Virtual file path | Prevents blob swapping between paths |
