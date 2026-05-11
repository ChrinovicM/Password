"""
vault_core.py — Pure vault logic, no GUI dependencies.
"""
from __future__ import annotations

import json
import base64
import secrets
import string
import hashlib
import hmac
import shutil
import logging
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("vault_core")


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

def generate_password(length: int = 16, use_upper: bool = True,
                      use_digits: bool = True, use_symbols: bool = True) -> str:
    """Generate a cryptographically strong random password."""
    pool = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pool += symbols
        required.append(secrets.choice(symbols))

    remaining = [secrets.choice(pool) for _ in range(length - len(required))]
    combined = required + remaining
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)


def password_strength(password: str) -> tuple[int, str]:
    """
    Returns (score 0-4, label).
    0=Very Weak, 1=Weak, 2=Fair, 3=Strong, 4=Very Strong
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 14:
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score = min(score + 1, 4)

    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return score, labels[min(score, 4)]


# ---------------------------------------------------------------------------
# PasswordVault
# ---------------------------------------------------------------------------

KDF_ITERATIONS = 390_000
SALT_SIZE = 16


class PasswordVault:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.salt: bytes | None = None
        self.verify: str | None = None
        self._key: bytes | None = None
        self.entries: list[dict] = []

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        raw = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, KDF_ITERATIONS
        )
        return base64.b64encode(raw).decode("utf-8")

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------

    def create(self, password: str) -> None:
        self.salt = secrets.token_bytes(SALT_SIZE)
        self.verify = self.hash_password(password, self.salt)
        self._key = self.derive_key(password, self.salt)
        self.entries = []
        self.save()
        logger.info("Vault created at %s", self.path)

    def load(self, password: str) -> None:
        if not self.exists():
            raise FileNotFoundError("Vault file not found.")

        with self.path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        self.salt = base64.b64decode(raw["salt"])
        self.verify = raw["verify"]

        if not hmac.compare_digest(self.hash_password(password, self.salt), self.verify):
            logger.warning("Failed unlock attempt")
            raise ValueError("Invalid master password.")

        self._key = self.derive_key(password, self.salt)
        try:
            decrypted = Fernet(self._key).decrypt(raw["token"].encode("utf-8"))
        except InvalidToken as exc:
            raise ValueError("Vault decryption failed.") from exc

        payload = json.loads(decrypted.decode("utf-8"))
        self.entries = payload.get("entries", [])
        logger.info("Vault unlocked successfully")

    def save(self) -> None:
        if self._key is None:
            raise ValueError("Vault is not unlocked.")

        # Backup previous file
        if self.path.exists():
            shutil.copy2(self.path, self.path.with_suffix(".json.bak"))

        payload = json.dumps({"entries": self.entries}, separators=(",", ":")).encode("utf-8")
        token = Fernet(self._key).encrypt(payload)
        data = {
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "verify": self.verify,
            "token": token.decode("utf-8"),
        }
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Re-derive key and re-encrypt entire vault under new master password."""
        self.load(old_password)  # validates old password
        self.salt = secrets.token_bytes(SALT_SIZE)
        self.verify = self.hash_password(new_password, self.salt)
        self._key = self.derive_key(new_password, self.salt)
        self.save()
        logger.info("Master password changed successfully")

    def clear(self) -> None:
        """Lock the vault and wipe the key from memory."""
        if self._key is not None:
            # Overwrite before releasing reference
            self._key = bytearray(len(self._key))
            self._key = None
        self.entries = []
        self.salt = None
        self.verify = None

    # ------------------------------------------------------------------
    # Entry CRUD
    # ------------------------------------------------------------------

    def add_entry(self, site: str, user: str, password: str, category: str = "General") -> dict:
        entry = {
            "id": secrets.token_hex(8),
            "site": site,
            "user": user,
            "pass": password,
            "category": category,
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
        }
        self.entries.append(entry)
        self.save()
        logger.info("Entry added for site: %s", site)
        return entry

    def update_entry(self, entry_id: str, site: str = None, user: str = None,
                     password: str = None, category: str = None) -> bool:
        for item in self.entries:
            if item.get("id") == entry_id:
                if site is not None:
                    item["site"] = site
                if user is not None:
                    item["user"] = user
                if password is not None:
                    item["pass"] = password
                    item["updated"] = datetime.now().isoformat()
                if category is not None:
                    item["category"] = category
                self.save()
                logger.info("Entry updated: %s", entry_id)
                return True
        return False

    def remove_entry_by_id(self, entry_id: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.get("id") != entry_id]
        if len(self.entries) < before:
            self.save()
            logger.info("Entry removed: %s", entry_id)
            return True
        return False

    def find_matches(self, query: str, category: str = None) -> list[dict]:
        normalized = query.lower()
        results = [
            item for item in self.entries
            if normalized in item["site"].lower() or normalized in item["user"].lower()
        ]
        if category and category != "All":
            results = [r for r in results if r.get("category") == category]
        return results

    def get_all(self, category: str = None) -> list[dict]:
        if not category or category == "All":
            return list(self.entries)
        return [e for e in self.entries if e.get("category") == category]

    def get_categories(self) -> list[str]:
        cats = sorted({e.get("category", "General") for e in self.entries})
        return ["All"] + cats

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def export_json(self, dest_path: Path, master_password: str) -> None:
        """Export decrypted entries to JSON (requires master password confirmation)."""
        if not hmac.compare_digest(self.hash_password(master_password, self.salt), self.verify):
            raise ValueError("Invalid master password.")
        with dest_path.open("w", encoding="utf-8") as fh:
            json.dump({"exported": datetime.now().isoformat(), "entries": self.entries}, fh, indent=2)
        logger.info("Vault exported to %s", dest_path)

    def export_csv(self, dest_path: Path, master_password: str) -> None:
        """Export decrypted entries to CSV."""
        if not hmac.compare_digest(self.hash_password(master_password, self.salt), self.verify):
            raise ValueError("Invalid master password.")
        import csv
        with dest_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["site", "user", "pass", "category", "created", "updated"])
            writer.writeheader()
            for entry in self.entries:
                writer.writerow({k: entry.get(k, "") for k in writer.fieldnames})
        logger.info("Vault exported to CSV: %s", dest_path)

    def import_json(self, src_path: Path) -> int:
        """Import entries from a previously exported JSON file. Returns count added."""
        with src_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        imported = data.get("entries", [])
        existing_ids = {e.get("id") for e in self.entries}
        added = 0
        for entry in imported:
            if entry.get("id") not in existing_ids:
                # Ensure required fields
                entry.setdefault("id", secrets.token_hex(8))
                entry.setdefault("category", "General")
                entry.setdefault("created", datetime.now().isoformat())
                entry.setdefault("updated", datetime.now().isoformat())
                self.entries.append(entry)
                added += 1
        if added:
            self.save()
        logger.info("Imported %d entries from %s", added, src_path)
        return added
