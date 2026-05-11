"""
tests/test_vault_core.py — pytest suite for vault_core.py
Run with:  pytest tests/ -v
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_core import PasswordVault, generate_password, password_strength


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_vault(tmp_path):
    """A fresh PasswordVault backed by a temp file."""
    v = PasswordVault(tmp_path / "vault.json")
    v.create("SecurePass123!")
    return v


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

class TestGeneratePassword:
    def test_default_length(self):
        pw = generate_password(16)
        assert len(pw) == 16

    def test_custom_length(self):
        for n in (8, 20, 64):
            assert len(generate_password(n)) == n

    def test_has_uppercase(self):
        pw = generate_password(20, use_upper=True, use_digits=False, use_symbols=False)
        assert any(c.isupper() for c in pw)

    def test_has_digits(self):
        pw = generate_password(20, use_upper=False, use_digits=True, use_symbols=False)
        assert any(c.isdigit() for c in pw)

    def test_has_symbols(self):
        import string
        pw = generate_password(20, use_upper=False, use_digits=False, use_symbols=True)
        assert any(c in string.punctuation for c in pw)

    def test_randomness(self):
        passwords = {generate_password(16) for _ in range(20)}
        assert len(passwords) > 15  # should not repeat


class TestPasswordStrength:
    def test_very_weak(self):
        score, label = password_strength("abc")
        assert score <= 1

    def test_strong(self):
        score, label = password_strength("G7!xQpLm@9#rZ2kN")
        assert score >= 3

    def test_returns_label(self):
        _, label = password_strength("hello")
        assert isinstance(label, str)
        assert label in ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


# ---------------------------------------------------------------------------
# Vault lifecycle
# ---------------------------------------------------------------------------

class TestVaultLifecycle:
    def test_create_writes_file(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("MyPassword123!")
        assert (tmp_path / "v.json").exists()

    def test_load_correct_password(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("Correct1234!")
        v2 = PasswordVault(tmp_path / "v.json")
        v2.load("Correct1234!")  # should not raise

    def test_load_wrong_password(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("RightPass123!")
        v2 = PasswordVault(tmp_path / "v.json")
        with pytest.raises(ValueError, match="Invalid master password"):
            v2.load("WrongPass999!")

    def test_load_missing_file(self, tmp_path):
        v = PasswordVault(tmp_path / "nonexistent.json")
        with pytest.raises(FileNotFoundError):
            v.load("anything")

    def test_backup_created_on_save(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("Pass123!abc")
        v.add_entry("site.com", "user", "pw123")
        assert (tmp_path / "v.json.bak").exists()

    def test_clear_wipes_key(self, tmp_vault):
        tmp_vault.clear()
        assert tmp_vault._key is None
        assert tmp_vault.entries == []

    def test_change_master_password(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("OldPass123!")
        v.add_entry("example.com", "alice", "secret99")
        v.change_master_password("OldPass123!", "NewPass456!")

        v2 = PasswordVault(tmp_path / "v.json")
        with pytest.raises(ValueError):
            v2.load("OldPass123!")

        v3 = PasswordVault(tmp_path / "v.json")
        v3.load("NewPass456!")
        assert len(v3.entries) == 1
        assert v3.entries[0]["site"] == "example.com"


# ---------------------------------------------------------------------------
# Entry CRUD
# ---------------------------------------------------------------------------

class TestEntryCRUD:
    def test_add_entry(self, tmp_vault):
        entry = tmp_vault.add_entry("github.com", "alice", "gh_pass_123")
        assert entry["site"] == "github.com"
        assert len(tmp_vault.entries) == 1

    def test_entry_has_id(self, tmp_vault):
        entry = tmp_vault.add_entry("site.com", "bob", "pw")
        assert "id" in entry and len(entry["id"]) > 0

    def test_entry_has_timestamps(self, tmp_vault):
        entry = tmp_vault.add_entry("site.com", "bob", "pw")
        assert "created" in entry
        assert "updated" in entry

    def test_add_multiple_entries(self, tmp_vault):
        for i in range(5):
            tmp_vault.add_entry(f"site{i}.com", f"user{i}", f"pass{i}")
        assert len(tmp_vault.entries) == 5

    def test_update_entry(self, tmp_vault):
        entry = tmp_vault.add_entry("old.com", "user", "oldpw")
        eid = entry["id"]
        result = tmp_vault.update_entry(eid, site="new.com", password="newpw")
        assert result is True
        updated = next(e for e in tmp_vault.entries if e["id"] == eid)
        assert updated["site"] == "new.com"
        assert updated["pass"] == "newpw"

    def test_update_nonexistent(self, tmp_vault):
        result = tmp_vault.update_entry("badid", site="x.com")
        assert result is False

    def test_remove_entry_by_id(self, tmp_vault):
        entry = tmp_vault.add_entry("del.com", "user", "pw")
        eid = entry["id"]
        result = tmp_vault.remove_entry_by_id(eid)
        assert result is True
        assert all(e["id"] != eid for e in tmp_vault.entries)

    def test_remove_nonexistent(self, tmp_vault):
        result = tmp_vault.remove_entry_by_id("nope")
        assert result is False


# ---------------------------------------------------------------------------
# Search & filter
# ---------------------------------------------------------------------------

class TestSearchFilter:
    def setup_method(self):
        pass

    def test_find_by_site(self, tmp_vault):
        tmp_vault.add_entry("github.com", "alice", "pw1", "Dev")
        tmp_vault.add_entry("gmail.com", "alice", "pw2", "Email")
        results = tmp_vault.find_matches("github")
        assert len(results) == 1
        assert results[0]["site"] == "github.com"

    def test_find_by_user(self, tmp_vault):
        tmp_vault.add_entry("site.com", "alice@example.com", "pw")
        results = tmp_vault.find_matches("alice")
        assert len(results) == 1

    def test_find_case_insensitive(self, tmp_vault):
        tmp_vault.add_entry("GitHub.com", "User", "pw")
        results = tmp_vault.find_matches("github")
        assert len(results) == 1

    def test_find_no_match(self, tmp_vault):
        tmp_vault.add_entry("site.com", "user", "pw")
        results = tmp_vault.find_matches("zzznomatch")
        assert results == []

    def test_get_all(self, tmp_vault):
        tmp_vault.add_entry("a.com", "u", "p", "Cat1")
        tmp_vault.add_entry("b.com", "u", "p", "Cat2")
        all_entries = tmp_vault.get_all()
        assert len(all_entries) == 2

    def test_get_by_category(self, tmp_vault):
        tmp_vault.add_entry("a.com", "u", "p", "Work")
        tmp_vault.add_entry("b.com", "u", "p", "Personal")
        results = tmp_vault.get_all("Work")
        assert len(results) == 1
        assert results[0]["site"] == "a.com"

    def test_get_categories(self, tmp_vault):
        tmp_vault.add_entry("a.com", "u", "p", "Work")
        tmp_vault.add_entry("b.com", "u", "p", "Personal")
        cats = tmp_vault.get_categories()
        assert "All" in cats
        assert "Work" in cats
        assert "Personal" in cats


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

class TestExportImport:
    def test_export_json(self, tmp_vault, tmp_path):
        tmp_vault.add_entry("site.com", "user", "pw123")
        out = tmp_path / "export.json"
        tmp_vault.export_json(out, "SecurePass123!")
        with out.open() as f:
            data = json.load(f)
        assert "entries" in data
        assert data["entries"][0]["site"] == "site.com"

    def test_export_wrong_password(self, tmp_vault, tmp_path):
        out = tmp_path / "export.json"
        with pytest.raises(ValueError):
            tmp_vault.export_json(out, "WrongPassword!")

    def test_export_csv(self, tmp_vault, tmp_path):
        tmp_vault.add_entry("csv.com", "user", "pw")
        out = tmp_path / "export.csv"
        tmp_vault.export_csv(out, "SecurePass123!")
        content = out.read_text()
        assert "csv.com" in content
        assert "site" in content  # header

    def test_import_json(self, tmp_vault, tmp_path):
        # Export first
        out = tmp_path / "export.json"
        tmp_vault.add_entry("site.com", "user", "pw")
        tmp_vault.export_json(out, "SecurePass123!")

        # Import into fresh vault
        v2 = PasswordVault(tmp_path / "v2.json")
        v2.create("AnotherPass456!")
        added = v2.import_json(out)
        assert added == 1
        assert v2.entries[0]["site"] == "site.com"

    def test_import_no_duplicates(self, tmp_vault, tmp_path):
        entry = tmp_vault.add_entry("site.com", "user", "pw")
        out = tmp_path / "export.json"
        tmp_vault.export_json(out, "SecurePass123!")

        # Import into same vault
        added = tmp_vault.import_json(out)
        assert added == 0  # duplicate skipped
        assert len(tmp_vault.entries) == 1


# ---------------------------------------------------------------------------
# Persistence round-trip
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_entries_survive_reload(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("StrongPass999!")
        v.add_entry("example.com", "alice", "secretpw", "Social")

        v2 = PasswordVault(tmp_path / "v.json")
        v2.load("StrongPass999!")
        assert len(v2.entries) == 1
        assert v2.entries[0]["site"] == "example.com"
        assert v2.entries[0]["pass"] == "secretpw"
        assert v2.entries[0]["category"] == "Social"

    def test_multiple_saves_preserve_data(self, tmp_path):
        v = PasswordVault(tmp_path / "v.json")
        v.create("Pass1234!abc")
        for i in range(10):
            v.add_entry(f"site{i}.com", f"user{i}", f"pw{i}")

        v2 = PasswordVault(tmp_path / "v.json")
        v2.load("Pass1234!abc")
        assert len(v2.entries) == 10
