import os
import pytest
from pathlib import Path
from vault import Vault, VaultError, WrongPasswordError, TamperedError, analyse_password

@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "test_vault.ykc")

@pytest.fixture
def password():
    return "StrongP@ssw0rd123!"

def test_analyse_password():
    res = analyse_password("short")
    assert res["rating"] == "Weak"
    assert any("Too short" in issue for issue in res["issues"])

    res = analyse_password("VeryStrongP@ssw0rdWithMoreChars!NoSequences")
    assert res["rating"] == "Strong"
    assert res["score"] >= 75

def test_vault_create_and_open(vault_path, password):
    # Create vault
    v = Vault.create(vault_path, password)
    assert v.is_open()
    assert os.path.exists(vault_path)
    v.close()
    assert not v.is_open()

    # Open vault
    v2 = Vault.open(vault_path, password)
    assert v2.is_open()
    v2.close()

def test_vault_create_min_password(vault_path):
    with pytest.raises(VaultError, match="Password must be at least 8 characters"):
        Vault.create(vault_path, "short")

def test_vault_create_already_exists(vault_path, password):
    Path(vault_path).touch()
    with pytest.raises(VaultError, match="File already exists"):
        Vault.create(vault_path, password)

def test_vault_open_wrong_password(vault_path, password):
    Vault.create(vault_path, password).close()
    with pytest.raises(WrongPasswordError):
        Vault.open(vault_path, "WrongPassword!")

def test_vault_file_operations(vault_path, password):
    v = Vault.create(vault_path, password)

    file_path = "documents/test.txt"
    data = b"Hello, World!"

    # Write
    v.write_file(file_path, data)

    # Read
    assert v.read_file(file_path) == data

    # List
    files = v.list_files()
    assert len(files) == 1
    assert files[0]["path"] == file_path
    assert files[0]["size"] == len(data)

    # Info
    info = v.get_file_info(file_path)
    assert info["size"] == len(data)

    # Delete
    v.delete_file(file_path)
    assert len(v.list_files()) == 0
    with pytest.raises(FileNotFoundError):
        v.read_file(file_path)

    v.close()

def test_vault_rename_file(vault_path, password):
    v = Vault.create(vault_path, password)
    old_path = "old.txt"
    new_path = "new.txt"
    data = b"Rename test"

    v.write_file(old_path, data)
    v.rename_file(old_path, new_path)

    assert v.read_file(new_path) == data
    with pytest.raises(FileNotFoundError):
        v.read_file(old_path)

    v.close()

def test_vault_integrity_check(vault_path, password):
    v = Vault.create(vault_path, password)
    v.write_file("test.txt", b"Integrity check data")

    res = v.check_integrity()
    assert len(res["ok"]) == 1
    assert len(res["corrupted"]) == 0

    v.close()

def test_vault_compact(vault_path, password):
    v = Vault.create(vault_path, password)
    v.write_file("large.bin", os.urandom(1024 * 100))
    v.delete_file("large.bin")

    before, after = v.compact()
    # It might or might not be smaller depending on SQLite's vacuum,
    # but it should succeed.
    assert after <= before
    assert v.is_open()
    v.close()

def test_vault_backup(vault_path, password, tmp_path):
    v = Vault.create(vault_path, password)
    v.write_file("test.txt", b"Backup data")

    backup_path = str(tmp_path / "backup.ykc")
    v.backup(backup_path)

    assert os.path.exists(backup_path)
    v_backup = Vault.open(backup_path, password)
    assert v_backup.read_file("test.txt") == b"Backup data"
    v_backup.close()
    v.close()

def test_vault_recovery(vault_path, password, tmp_path):
    v = Vault.create(vault_path, password)
    v.write_file("file1.txt", b"Recover me")
    v.write_file("folder/file2.txt", b"Recover me too")

    recovery_dir = str(tmp_path / "recovery")
    res = v.recover_readable(recovery_dir)

    assert len(res["recovered"]) == 2
    assert (Path(recovery_dir) / "file1.txt").read_bytes() == b"Recover me"
    assert (Path(recovery_dir) / "folder" / "file2.txt").read_bytes() == b"Recover me too"

    v.close()

def test_vault_temp_file_handling(vault_path, password):
    v = Vault.create(vault_path, password)
    v.write_file("test.txt", b"Original content")

    # Extract
    tmp_file = v.extract_to_temp("test.txt")
    assert os.path.exists(tmp_file)
    assert Path(tmp_file).read_bytes() == b"Original content"

    # Modify and reimport
    with open(tmp_file, "wb") as f:
        f.write(b"Updated content")
    v.reimport_temp("test.txt", tmp_file)

    assert v.read_file("test.txt") == b"Updated content"
    assert not os.path.exists(tmp_file)

    v.close()

def test_vault_stats(vault_path, password):
    v = Vault.create(vault_path, password)
    v.write_file("file1.txt", b"data1")
    v.write_file("file2.txt", b"data22")

    stats = v.vault_stats()
    assert stats["file_count"] == 2
    assert stats["total_size"] == 5 + 6
    assert stats["db_size"] > 0

    v.close()
