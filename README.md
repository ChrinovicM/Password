# 🛡️ Encrypted Password Vault

A secure, fully-featured local password manager built in Python with Tkinter.

---

## Features

| Category | Feature |
|---|---|
| **Security** | AES-256 encryption via Fernet, PBKDF2-HMAC-SHA256 key derivation |
| **Security** | Failed login lockout (5 attempts → 30s cooldown) |
| **Security** | Auto-lock on inactivity (default: 120s) |
| **Security** | Secure memory wipe on vault lock |
| **Security** | Clipboard auto-clear after 15 seconds |
| **Security** | Master password change (re-encrypts entire vault) |
| **Entries** | Add, edit, remove entries with category tagging |
| **Entries** | Per-entry timestamps + age warning (>90 days) |
| **Entries** | Entry-level reveal (requires master password re-entry) |
| **Entries** | Copy password or username to clipboard |
| **Generator** | Built-in password generator (length, uppercase, digits, symbols) |
| **Generator** | Live password strength meter on all password fields |
| **Search** | Real-time search by site or username |
| **Search** | Filter by category |
| **Backup** | Automatic `.json.bak` backup on every save |
| **Import/Export** | Export to JSON or CSV (password-protected) |
| **Import/Export** | Import from previously exported JSON |
| **UI** | Dark theme, keyboard shortcuts, monospace display |
| **Logging** | Rotating event log (`vault.log`) — no passwords stored |
| **Tests** | Full pytest suite for all vault logic |

---

## File Structure

```
password_vault/
├── password.py          # Main GUI application (entry point)
├── vault_core.py        # Pure vault logic (no GUI)
├── config.json          # User-adjustable settings
├── vault.json           # Encrypted vault (created on first run)
├── vault.json.bak       # Auto-backup of previous vault state
├── vault.log            # Audit log (events only, no passwords)
└── tests/
    └── test_vault_core.py  # pytest suite
```

---

## Setup

### 1. Install dependencies

```bash
pip install cryptography
```

### 2. Run the app

```bash
python password.py
```

On first launch, you'll be prompted to create a master password (minimum 10 characters).

### 3. Run tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Configuration (`config.json`)

| Key | Default | Description |
|---|---|---|
| `lock_timeout_seconds` | `120` | Seconds of inactivity before auto-lock |
| `clipboard_clear_ms` | `15000` | Milliseconds before clipboard is cleared |
| `max_failed_attempts` | `5` | Wrong attempts before lockout |
| `lockout_duration_seconds` | `30` | Duration of lockout in seconds |
| `password_warn_age_days` | `90` | Days after which a password shows an age warning |
| `default_password_length` | `16` | Default length for generated passwords |
| `theme` | `"dark"` | UI theme (only dark currently supported) |

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | Add new entry |
| `Ctrl+F` | Focus search box |
| `Ctrl+L` | Lock vault immediately |
| `Ctrl+G` | Open password generator |
| `Enter` | Unlock vault (on login screen) |

---

## Security Notes

- Your vault is encrypted with **AES-256** (Fernet). The encryption key is derived from your master password using **PBKDF2-HMAC-SHA256** with 390,000 iterations.
- **Your master password is never stored.** Only a salted hash is kept for verification.
- A backup (`vault.json.bak`) is written before every save — keep this in a safe place.
- The audit log (`vault.log`) records events like unlock attempts and entry changes, but **never** records passwords.
- Exported files contain **plaintext passwords** — store them securely and delete when done.

---

## Dependencies

- Python 3.10+
- `cryptography` (`pip install cryptography`)
- `tkinter` (included with standard Python on Windows/macOS; on Linux: `sudo apt install python3-tk`)
- `pytest` (for tests only)
