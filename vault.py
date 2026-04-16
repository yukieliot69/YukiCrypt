"""
vault.py
~~~~~~~~
YukiCrypt encrypted vault engine.

Security design:
  - AES-256-GCM authenticated encryption (detects tampering)
  - Argon2id key derivation (GPU-resistant, memory-hard)
  - File path used as AAD — can't swap encrypted blobs between paths
  - Nonce is 96-bit random, never reused (probability of collision: negligible)
  - Temp files overwritten with os.urandom() before deletion
  - Master key zeroed from memory on vault close
  - SQLite WAL mode + path index — fast, crash-safe
  - All filenames are also encrypted — attacker can't see what's inside
"""

import os
import re
import time
import math
import ctypes
import sqlite3
import logging
import tempfile
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ── Optional Argon2 (stronger KDF) ──────────────────────────────────────────
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

VAULT_VERSION    = 1
SALT_SIZE        = 32
NONCE_SIZE       = 12   # AES-GCM standard
KEY_SIZE         = 32   # AES-256
MIN_PASSWORD_LEN = 8


class VaultError(Exception):       pass
class WrongPasswordError(VaultError): pass
class TamperedError(VaultError):   pass


# ── Key derivation ───────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key. Argon2id if available, PBKDF2-SHA512 fallback."""
    pw_bytes = password.encode("utf-8")

    if HAS_ARGON2:
        key = hash_secret_raw(
            pw_bytes, salt,
            time_cost=3,
            memory_cost=65536,   # 64 MB RAM — defeats GPU brute-force
            parallelism=4,
            hash_len=KEY_SIZE,
            type=Argon2Type.ID,
        )
    else:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=KEY_SIZE,
            salt=salt,
            iterations=600_000,
        )
        key = kdf.derive(pw_bytes)

    # Best-effort wipe of password bytes from CPython memory
    try:
        ctypes.memset(id(pw_bytes) + 20, 0, len(pw_bytes))
    except Exception:
        pass

    return key


# ── Password strength ────────────────────────────────────────────────────────

def analyse_password(password: str) -> dict:
    score, issues = 0, []
    length = len(password)

    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    elif length < 12:
        score += 20
        issues.append("Use 12+ characters for better security")
    elif length < 20:
        score += 40
    else:
        score += 60

    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
    score += sum([has_lower, has_upper, has_digit, has_symbol]) * 8

    if not has_upper:  issues.append("Add uppercase letters")
    if not has_digit:  issues.append("Add numbers")
    if not has_symbol: issues.append("Add symbols (!@#$...)")

    if re.search(r'(.)\1{2,}', password):
        score -= 10; issues.append("Avoid repeated characters")
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd)', password.lower()):
        score -= 10; issues.append("Avoid sequential patterns")

    charset = (26 if has_lower else 0) + (26 if has_upper else 0) + \
              (10 if has_digit else 0) + (32 if has_symbol else 0)
    entropy = length * math.log2(max(charset, 1))
    score   = max(0, min(100, score))

    rating = "Weak" if score < 30 else "Fair" if score < 55 else \
             "Good" if score < 75 else "Strong"

    return {"score": score, "rating": rating,
            "issues": issues, "entropy": round(entropy, 1)}


# ── Vault ────────────────────────────────────────────────────────────────────

class Vault:
    """AES-256-GCM encrypted file vault backed by SQLite."""

    def __init__(self):
        self._db:    Optional[sqlite3.Connection] = None
        self._key:   Optional[bytes]              = None
        self._aesgcm: Optional[AESGCM]            = None
        self._path:  Optional[str]                = None
        self._lock   = threading.RLock()
        self._open_temps: list[str]               = []
        # FIX #1: in-memory path→id index avoids O(n) decrypt scan per lookup
        self._path_index: dict[str, int]          = {}

    # ── Create / open / close ────────────────────────────────────────────────

    @classmethod
    def create(cls, vault_path: str, password: str) -> "Vault":
        if len(password) < MIN_PASSWORD_LEN:
            raise VaultError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if os.path.exists(vault_path):
            raise VaultError(f"File already exists: {vault_path}")

        salt = os.urandom(SALT_SIZE)
        key  = _derive_key(password, salt)

        db = sqlite3.connect(vault_path, check_same_thread=False)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")

            db.execute("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)
            """)
            db.execute("""
                CREATE TABLE files (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    enc_path    BLOB NOT NULL UNIQUE,
                    path_nonce  BLOB NOT NULL,
                    enc_data    BLOB NOT NULL,
                    data_nonce  BLOB NOT NULL,
                    size        INTEGER NOT NULL,
                    modified    INTEGER NOT NULL,
                    mime_hint   TEXT
                )
            """)
            db.execute("CREATE INDEX idx_enc_path ON files(enc_path)")

            kdf = f"{'argon2id' if HAS_ARGON2 else 'pbkdf2-sha512'}:v{VAULT_VERSION}"
            db.execute("INSERT INTO meta VALUES ('version', ?)", (str(VAULT_VERSION),))
            db.execute("INSERT INTO meta VALUES ('salt',    ?)", (salt,))
            db.execute("INSERT INTO meta VALUES ('kdf',     ?)", (kdf.encode(),))

            aesgcm = AESGCM(key)
            vn     = os.urandom(NONCE_SIZE)
            vc     = aesgcm.encrypt(vn, b"SAFEBOX_OK", b"verify")
            db.execute("INSERT INTO meta VALUES ('verify_nonce', ?)", (vn,))
            db.execute("INSERT INTO meta VALUES ('verify_ct',    ?)", (vc,))
            db.commit()
        except Exception:
            db.close()
            # Remove partial vault file so user doesn't see a broken .ykc
            try:
                os.remove(vault_path)
            except Exception:
                pass
            raise

        v = cls()
        v._db     = db
        v._key    = key
        v._aesgcm = aesgcm
        v._path   = vault_path
        try:
            v._build_index()
        except Exception:
            db.close()
            try:
                os.remove(vault_path)
            except Exception:
                pass
            raise
        log.info(f"Vault created: {vault_path}")
        return v

    @classmethod
    def open(cls, vault_path: str, password: str) -> "Vault":
        if not os.path.exists(vault_path):
            raise VaultError(f"Vault not found: {vault_path}")

        db = sqlite3.connect(vault_path, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")

        def _meta(k):
            row = db.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
            if not row:
                raise VaultError(f"Corrupt vault: missing '{k}'")
            return row[0]

        try:
            salt         = _meta("salt")
            verify_nonce = _meta("verify_nonce")
            verify_ct    = _meta("verify_ct")

            key    = _derive_key(password, salt)
            aesgcm = AESGCM(key)

            try:
                pt = aesgcm.decrypt(verify_nonce, verify_ct, b"verify")
                if pt != b"SAFEBOX_OK":
                    raise WrongPasswordError("Incorrect password.")
            except InvalidTag:
                raise WrongPasswordError("Incorrect password.")
        except Exception:
            db.close()
            raise

        v = cls()
        v._db     = db
        v._key    = key
        v._aesgcm = aesgcm
        v._path   = vault_path
        try:
            v._build_index()
        except Exception:
            db.close()
            raise
        log.info(f"Vault opened: {vault_path}")
        return v

    def close(self):
        with self._lock:
            if self._key:
                try:
                    ctypes.memset(id(self._key) + 20, 0, len(self._key))
                except Exception:
                    pass
                self._key    = None
                self._aesgcm = None
            self._path_index.clear()
            if self._db:
                self._db.close()
                self._db = None

    def is_open(self) -> bool:
        return self._db is not None and self._key is not None

    # ── Internal: index & crypto ─────────────────────────────────────────────

    def _build_index(self):
        """
        FIX #1 & #2: Build path→id index by decrypting only path columns.
        list_files() and _find_id() use this — never touch enc_data just to list files.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT id, path_nonce, enc_path FROM files"
            ).fetchall()
            self._path_index.clear()
            for fid, path_nonce, enc_path in rows:
                try:
                    vpath = self._aesgcm.decrypt(
                        path_nonce, enc_path, b"path"
                    ).decode("utf-8")
                    self._path_index[vpath] = fid
                except Exception:
                    pass  # corrupted path — skip from index

    def _find_id(self, virtual_path: str) -> Optional[int]:
        """O(1) lookup via in-memory index. FIX #1."""
        return self._path_index.get(virtual_path)

    def _encrypt(self, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_SIZE)
        return nonce, self._aesgcm.encrypt(nonce, data, aad)

    def _decrypt(self, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
        try:
            return self._aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise TamperedError("Authentication failed — data may be corrupted or tampered.")

    # ── File operations ──────────────────────────────────────────────────────

    def write_file(self, virtual_path: str, data: bytes):
        with self._lock:
            virtual_path = self._normalize(virtual_path)
            aad          = virtual_path.encode("utf-8")

            path_nonce, enc_path = self._encrypt(virtual_path.encode(), b"path")
            data_nonce, enc_data = self._encrypt(data, aad)
            ext = Path(virtual_path).suffix.lower()
            now = int(time.time())

            # FIX #4: DELETE old row first if path exists, then INSERT fresh.
            # INSERT OR REPLACE cannot match because enc_path changes every write.
            existing_id = self._find_id(virtual_path)
            # Wrap DELETE + INSERT in explicit transaction so a crash between
            # the two operations can't leave the file deleted but not replaced.
            self._db.execute("BEGIN")
            try:
                if existing_id is not None:
                    self._db.execute(
                        "UPDATE files SET enc_data=?, data_nonce=? WHERE id=?",
                        (os.urandom(64), os.urandom(NONCE_SIZE), existing_id)
                    )
                    self._db.execute("DELETE FROM files WHERE id=?", (existing_id,))
                cursor = self._db.execute(
                    """INSERT INTO files
                       (enc_path, path_nonce, enc_data, data_nonce, size, modified, mime_hint)
                       VALUES (?,?,?,?,?,?,?)""",
                    (enc_path, path_nonce, enc_data, data_nonce, len(data), now, ext)
                )
                new_id = cursor.lastrowid
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            # Use lastrowid — no extra SELECT needed after commit
            if new_id:
                self._path_index[virtual_path] = new_id

    def read_file(self, virtual_path: str) -> bytes:
        with self._lock:
            virtual_path = self._normalize(virtual_path)
            fid = self._find_id(virtual_path)
            if fid is None:
                raise FileNotFoundError(virtual_path)
            row = self._db.execute(
                "SELECT data_nonce, enc_data FROM files WHERE id=?", (fid,)
            ).fetchone()
            if not row:
                raise FileNotFoundError(virtual_path)
            data_nonce, enc_data = row
            return self._decrypt(data_nonce, enc_data, virtual_path.encode())

    def delete_file(self, virtual_path: str):
        with self._lock:
            virtual_path = self._normalize(virtual_path)
            fid = self._find_id(virtual_path)
            if fid is None:
                raise FileNotFoundError(virtual_path)
            # Wipe encrypted blob then delete — wrapped in transaction
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "UPDATE files SET enc_data=?, data_nonce=? WHERE id=?",
                    (os.urandom(64), os.urandom(NONCE_SIZE), fid)
                )
                self._db.execute("DELETE FROM files WHERE id=?", (fid,))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            self._path_index.pop(virtual_path, None)

    def rename_file(self, old_path: str, new_path: str):
        """Rename a file. Holds lock across the full read-write-delete sequence."""
        with self._lock:
            data = self.read_file(old_path)
            self.write_file(new_path, data)
            self.delete_file(old_path)

    def list_files(self) -> list[dict]:
        """
        FIX #2: Fetch only metadata columns — never loads enc_data blobs.
        Uses the in-memory index for paths.
        """
        with self._lock:
            # snapshot index so we don't hold lock during sort
            index_snapshot = dict(self._path_index)
            rows = self._db.execute(
                "SELECT id, size, modified, mime_hint FROM files"
            ).fetchall()

        # Build reverse map: id → vpath
        id_to_path = {v: k for k, v in index_snapshot.items()}

        result = []
        for fid, size, modified, ext in rows:
            vpath = id_to_path.get(fid)
            if vpath is None:
                continue   # corrupted path — skip
            result.append({
                "id":      fid,
                "path":    vpath,
                "name":    Path(vpath).name,
                "folder":  "/".join(Path(vpath).parent.parts) if "/" in vpath else "",
                "size":    size,
                "modified": modified,
                "ext":     (ext or ""),
                "is_keep": Path(vpath).name == ".keep",
            })

        result.sort(key=lambda x: (x["folder"], x["name"].lower()))
        return result

    def get_file_info(self, virtual_path: str) -> Optional[dict]:
        with self._lock:
            fid = self._find_id(virtual_path)
            if fid is None:
                return None
            row = self._db.execute(
                "SELECT size, modified, mime_hint FROM files WHERE id=?", (fid,)
            ).fetchone()
            if not row:
                return None
            size, modified, ext = row
            return {"path": virtual_path, "size": size,
                    "modified": modified, "ext": ext or ""}

    def vault_stats(self) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size),0) FROM files"
            ).fetchone()
            file_count, total_size = row
            db_size = os.path.getsize(self._path) if self._path else 0
        return {
            "file_count": file_count,
            "total_size": total_size,
            "db_size":    db_size,
            "kdf":        "Argon2id" if HAS_ARGON2 else "PBKDF2-SHA512",
            "cipher":     "AES-256-GCM",
        }

    # ── Temp file handling ───────────────────────────────────────────────────

    def extract_to_temp(self, virtual_path: str) -> str:
        """Decrypt to a secure temp file. Caller must call secure_delete_temp() after."""
        data = self.read_file(virtual_path)
        ext  = Path(virtual_path).suffix
        fd, tmp_path = tempfile.mkstemp(suffix=ext, prefix="sb_")
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._open_temps.append(tmp_path)
        return tmp_path

    def secure_delete_temp(self, tmp_path: str):
        """3-pass overwrite then delete."""
        if tmp_path in self._open_temps:
            self._open_temps.remove(tmp_path)
        try:
            size = os.path.getsize(tmp_path)
            with open(tmp_path, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(max(size, 1)))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(tmp_path)
        except Exception as e:
            log.warning(f"Secure delete failed: {e}")
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    def reimport_temp(self, virtual_path: str, tmp_path: str):
        with open(tmp_path, "rb") as f:
            data = f.read()
        self.write_file(virtual_path, data)   # raises on failure
        self.secure_delete_temp(tmp_path)     # only reached if write succeeded

    # ── Integrity / backup / recovery ────────────────────────────────────────

    def check_integrity(self, progress_cb=None) -> dict:
        """Verify every file's AES-GCM tag. Detects corruption and tampering."""
        # FIX #3: snapshot all data inside the lock, then verify outside
        with self._lock:
            rows = self._db.execute(
                "SELECT id, path_nonce, enc_path, data_nonce, enc_data FROM files"
            ).fetchall()

        ok, corrupted = [], []

        for i, (fid, path_nonce, enc_path, data_nonce, enc_data) in enumerate(rows):
            if progress_cb:
                progress_cb(i + 1, len(rows))
            try:
                vpath = self._aesgcm.decrypt(
                    path_nonce, enc_path, b"path"
                ).decode("utf-8")
            except Exception:
                corrupted.append(f"<unknown id={fid}>")
                continue
            try:
                self._aesgcm.decrypt(data_nonce, enc_data, vpath.encode())
                ok.append(vpath)
            except Exception:
                corrupted.append(vpath)

        return {"ok": ok, "corrupted": corrupted, "total": len(rows)}

    def recover_readable(self, output_dir: str, progress_cb=None) -> dict:
        """Extract every decryptable file to output_dir, skip corrupted ones."""
        os.makedirs(output_dir, exist_ok=True)

        with self._lock:
            rows = self._db.execute(
                "SELECT id, path_nonce, enc_path, data_nonce, enc_data FROM files"
            ).fetchall()

        recovered, failed = [], []

        for i, (fid, path_nonce, enc_path, data_nonce, enc_data) in enumerate(rows):
            if progress_cb:
                progress_cb(i + 1, len(rows))
            try:
                vpath = self._aesgcm.decrypt(
                    path_nonce, enc_path, b"path"
                ).decode("utf-8")
            except Exception:
                failed.append(f"<unknown id={fid}>")
                continue

            if Path(vpath).name == ".keep":
                continue

            try:
                data     = self._aesgcm.decrypt(data_nonce, enc_data, vpath.encode())
                out_path = os.path.join(output_dir, vpath.replace("/", os.sep))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                recovered.append(vpath)
            except Exception as e:
                failed.append(vpath)
                log.warning(f"Recovery failed for {vpath}: {e}")

        return {"recovered": recovered, "failed": failed}

    def compact(self):
        """
        Reclaim free space using VACUUM INTO.
        WAL mode prevents in-place VACUUM from shrinking the file, so we use
        VACUUM INTO to create a compact copy then atomically replace the original.
        Returns (size_before, size_after) in bytes.
        """
        with self._lock:
            if not self._path:
                return 0, 0

            size_before  = os.path.getsize(self._path)
            tmp_path     = self._path + ".compact_tmp"

            try:
                # VACUUM INTO works with WAL mode — creates compacted copy
                self._db.execute(f'VACUUM INTO "{tmp_path}"')

                size_after = os.path.getsize(tmp_path)

                # Only replace if we actually saved space
                if size_after < size_before:
                    self._db.close()
                    os.replace(tmp_path, self._path)
                    # Re-open the compacted file
                    self._db = sqlite3.connect(
                        self._path, check_same_thread=False
                    )
                    self._db.execute("PRAGMA journal_mode=WAL")
                    self._db.execute("PRAGMA synchronous=FULL")
                else:
                    os.remove(tmp_path)
                    size_after = size_before

            except Exception:
                # Clean up temp file if anything went wrong
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                raise

        log.info(f"Compacted: {size_before:,} → {size_after:,} bytes")
        return size_before, size_after

    def backup(self, backup_path: str):
        """
        Create a compact backup using VACUUM INTO.
        Unlike the SQLite backup API, VACUUM INTO copies only live data pages
        so the backup is already compact — free space from deleted files is
        not copied. Atomic: backup is either complete or not written at all.
        Returns (original_size, backup_size) in bytes.
        """
        with self._lock:
            original_size = os.path.getsize(self._path) if self._path else 0
            self._db.execute(f'VACUUM INTO "{backup_path}"')
            backup_size = os.path.getsize(backup_path)
        log.info(f"Backup created: {backup_path} ({backup_size:,} bytes)")
        return original_size, backup_size

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _normalize(self, path: str) -> str:
        return path.replace("\\", "/").strip("/")
