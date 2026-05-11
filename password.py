"""
password.py — Encrypted Password Vault (Full Featured)
Depends on: vault_core.py, config.json
"""
from __future__ import annotations

import json
import time
import logging
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, ttk
from pathlib import Path
from datetime import datetime, timedelta

from vault_core import PasswordVault, generate_password, password_strength

# ---------------------------------------------------------------------------
# Config & Logging
# ---------------------------------------------------------------------------

CONFIG_PATH = Path(__file__).with_name("config.json")
VAULT_FILE  = Path(__file__).with_name("vault.json")

with CONFIG_PATH.open() as _f:
    CFG = json.load(_f)

LOG_FILE = Path(__file__).with_name(CFG["log_file"])
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vault_ui")

LOCK_TIMEOUT   = CFG["lock_timeout_seconds"]
CLIPBOARD_MS   = CFG["clipboard_clear_ms"]
MAX_ATTEMPTS   = CFG["max_failed_attempts"]
LOCKOUT_DUR    = CFG["lockout_duration_seconds"]
WARN_AGE_DAYS  = CFG["password_warn_age_days"]

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

DARK = {
    "bg":         "#0f1117",
    "surface":    "#1a1d27",
    "surface2":   "#22263a",
    "accent":     "#4f8ef7",
    "accent2":    "#7c3aed",
    "danger":     "#e05252",
    "success":    "#3ecf72",
    "warn":       "#f0a500",
    "text":       "#e8eaf0",
    "subtext":    "#8890a8",
    "border":     "#2e3350",
    "entry_bg":   "#1e2236",
    "btn_fg":     "#ffffff",
    "mono":       ("Courier New", 10),
    "ui":         ("Segoe UI", 10),
    "ui_bold":    ("Segoe UI", 10, "bold"),
    "title":      ("Segoe UI", 14, "bold"),
}

STRENGTH_COLORS = ["#e05252", "#e07c52", "#e0c252", "#3ecf72", "#00e5ff"]

vault        = PasswordVault(VAULT_FILE)
last_activity = time.time()
failed_attempts = 0
lockout_until   = 0.0
_selected_entry_id: str | None = None
_reveal_active = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def reset_timer():
    global last_activity
    last_activity = time.time()


def now_ts() -> str:
    return datetime.now().isoformat()


def age_days(iso: str) -> int:
    try:
        dt = datetime.fromisoformat(iso)
        return (datetime.now() - dt).days
    except Exception:
        return 0


def apply_theme(widget, bg=None, fg=None):
    try:
        kw = {}
        if bg: kw["bg"] = bg
        if fg: kw["fg"] = fg
        widget.config(**kw)
    except tk.TclError:
        pass


# ---------------------------------------------------------------------------
# Vault setup / login
# ---------------------------------------------------------------------------

def ensure_vault() -> bool:
    if vault.exists():
        return True
    messagebox.showinfo("Vault Setup",
        "No vault found. You will create a new encrypted vault now.")
    while True:
        pw = simpledialog.askstring("Create Master Password",
            "Enter a strong master password (min 10 chars):", show="*")
        if pw is None:
            return False
        if len(pw) < 10:
            messagebox.showwarning("Too Short", "Use at least 10 characters.")
            continue
        confirm = simpledialog.askstring("Confirm Password",
            "Confirm your master password:", show="*")
        if confirm is None:
            return False
        if pw != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
            continue
        vault.create(pw)
        messagebox.showinfo("Created", "Vault created successfully!")
        logger.info("New vault created")
        return True


def check_login(event=None):
    global failed_attempts, lockout_until

    if time.time() < lockout_until:
        remaining = int(lockout_until - time.time())
        messagebox.showwarning("Locked Out",
            f"Too many failed attempts. Try again in {remaining}s.")
        return

    pw = ent_master.get().strip()
    if not pw:
        messagebox.showwarning("Missing", "Enter your master password.")
        return

    try:
        vault.load(pw)
    except (ValueError, FileNotFoundError):
        failed_attempts += 1
        logger.warning("Failed login attempt #%d", failed_attempts)
        remaining = MAX_ATTEMPTS - failed_attempts
        if failed_attempts >= MAX_ATTEMPTS:
            lockout_until = time.time() + LOCKOUT_DUR
            failed_attempts = 0
            messagebox.showerror("Locked Out",
                f"Too many wrong attempts. Locked for {LOCKOUT_DUR}s.")
        else:
            messagebox.showerror("Access Denied",
                f"Wrong password. {remaining} attempt(s) remaining.")
        ent_master.delete(0, tk.END)
        return

    failed_attempts = 0
    lockout_until = 0.0
    ent_master.delete(0, tk.END)
    login_frame.pack_forget()
    vault_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    reset_timer()
    refresh_category_menu()
    refresh_display()


def lock_vault():
    global _selected_entry_id, _reveal_active
    vault.clear()
    _selected_entry_id = None
    _reveal_active = False
    display_box.config(state=tk.NORMAL)
    display_box.delete(1.0, tk.END)
    display_box.config(state=tk.DISABLED)
    vault_frame.pack_forget()
    login_frame.pack(pady=70)
    root.clipboard_clear()
    logger.info("Vault locked")


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def format_entry(item: dict, reveal: bool = False) -> str:
    pw_display = item["pass"] if reveal else "•" * min(len(item["pass"]), 12)
    age = age_days(item.get("updated", item.get("created", now_ts())))
    age_warn = f" ⚠ {age}d old" if age > WARN_AGE_DAYS else ""
    cat = item.get("category", "General")
    return (
        f"[{cat}]  {item['site']}\n"
        f"  User: {item['user']}\n"
        f"  Pass: {pw_display}{age_warn}\n"
        f"  ID  : {item.get('id','')}\n"
        f"{'─'*60}\n"
    )


def refresh_display(query: str = "", category: str = "All", reveal: bool = False):
    display_box.config(state=tk.NORMAL)
    display_box.delete(1.0, tk.END)

    if query:
        entries = vault.find_matches(query, category if category != "All" else None)
    else:
        entries = vault.get_all(category if category != "All" else None)

    if not entries:
        display_box.insert(tk.END, "  No entries found.\n")
    else:
        for item in entries:
            display_box.insert(tk.END, format_entry(item, reveal=reveal))

    display_box.config(state=tk.DISABLED)


def refresh_category_menu():
    cats = vault.get_categories()
    menu = category_menu["menu"]
    menu.delete(0, tk.END)
    for cat in cats:
        menu.add_command(label=cat,
            command=lambda c=cat: (category_var.set(c), do_search()))
    if category_var.get() not in cats:
        category_var.set("All")


def do_search(event=None):
    reset_timer()
    refresh_display(
        query=ent_search.get().strip(),
        category=category_var.get(),
        reveal=_reveal_active,
    )


# ---------------------------------------------------------------------------
# Add / Edit / Remove
# ---------------------------------------------------------------------------

def open_add_dialog(prefill: dict = None, edit_id: str = None):
    """Unified add/edit dialog."""
    dialog = tk.Toplevel(root)
    dialog.title("Edit Entry" if edit_id else "Add Entry")
    dialog.geometry("420x420")
    dialog.config(bg=DARK["bg"])
    dialog.grab_set()

    fields = {}

    def lbl(text):
        tk.Label(dialog, text=text, bg=DARK["bg"], fg=DARK["subtext"],
                 font=DARK["ui"]).pack(anchor="w", padx=20, pady=(10,0))

    def ent(default="", show=None):
        e = tk.Entry(dialog, bg=DARK["entry_bg"], fg=DARK["text"],
                     insertbackground=DARK["text"], relief=tk.FLAT,
                     font=DARK["mono"], width=40)
        if show:
            e.config(show=show)
        if default:
            e.insert(0, default)
        e.pack(padx=20, pady=2, ipady=4)
        return e

    lbl("Website / Service")
    fields["site"] = ent(prefill.get("site","") if prefill else "")

    lbl("Username / Email")
    fields["user"] = ent(prefill.get("user","") if prefill else "")

    lbl("Category")
    fields["cat"] = ent(prefill.get("category","General") if prefill else "General")

    lbl("Password")
    pw_frame = tk.Frame(dialog, bg=DARK["bg"])
    pw_frame.pack(fill=tk.X, padx=20)
    fields["pass"] = tk.Entry(pw_frame, bg=DARK["entry_bg"], fg=DARK["text"],
                              insertbackground=DARK["text"], relief=tk.FLAT,
                              font=DARK["mono"], width=30, show="*")
    fields["pass"].pack(side=tk.LEFT, ipady=4)
    if prefill:
        fields["pass"].insert(0, prefill.get("pass",""))

    # Strength meter
    strength_var = tk.StringVar(value="")
    strength_lbl = tk.Label(dialog, textvariable=strength_var,
                             bg=DARK["bg"], fg=DARK["warn"], font=DARK["ui"])
    strength_lbl.pack()

    strength_bar = tk.Canvas(dialog, height=6, bg=DARK["surface"], highlightthickness=0, width=380)
    strength_bar.pack(padx=20, pady=2)

    def update_strength(*_):
        pw = fields["pass"].get()
        if not pw:
            strength_var.set("")
            strength_bar.delete("all")
            return
        score, label = password_strength(pw)
        color = STRENGTH_COLORS[score]
        strength_var.set(f"Strength: {label}")
        strength_lbl.config(fg=color)
        strength_bar.delete("all")
        width = int(380 * (score + 1) / 5)
        strength_bar.create_rectangle(0, 0, width, 6, fill=color, outline="")

    fields["pass"].bind("<KeyRelease>", update_strength)

    # Generate password button
    def gen_pw():
        pw = generate_password(
            length=CFG["default_password_length"],
            use_upper=True, use_digits=True, use_symbols=True
        )
        fields["pass"].config(show="")
        fields["pass"].delete(0, tk.END)
        fields["pass"].insert(0, pw)
        update_strength()

    btn_gen = tk.Button(pw_frame, text="⚡ Generate", command=gen_pw,
                        bg=DARK["accent2"], fg="white", relief=tk.FLAT,
                        font=DARK["ui"], padx=6)
    btn_gen.pack(side=tk.LEFT, padx=(6,0))

    # Toggle show
    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        fields["pass"].config(show="" if show_var.get() else "*")
    tk.Checkbutton(dialog, text="Show password", variable=show_var,
                   command=toggle_show, bg=DARK["bg"], fg=DARK["subtext"],
                   selectcolor=DARK["surface"], font=DARK["ui"],
                   activebackground=DARK["bg"]).pack(anchor="w", padx=20)

    def save():
        site = fields["site"].get().strip()
        user = fields["user"].get().strip()
        pw   = fields["pass"].get()
        cat  = fields["cat"].get().strip() or "General"

        if not site or not user or not pw:
            messagebox.showwarning("Missing Fields", "Site, username, and password are required.")
            return

        if edit_id:
            vault.update_entry(edit_id, site=site, user=user, password=pw, category=cat)
            logger.info("Entry edited: %s", edit_id)
        else:
            vault.add_entry(site, user, pw, cat)

        dialog.destroy()
        refresh_category_menu()
        refresh_display(ent_search.get().strip(), category_var.get(), _reveal_active)

    tk.Button(dialog, text="💾 Save", command=save,
              bg=DARK["success"], fg="white", relief=tk.FLAT,
              font=DARK["ui_bold"], padx=20, pady=6).pack(pady=14)


def add_password():
    reset_timer()
    open_add_dialog()


def edit_selected():
    reset_timer()
    entry = get_selected_entry()
    if not entry:
        messagebox.showwarning("No Selection", "Select an entry from the list first.")
        return
    open_add_dialog(prefill=entry, edit_id=entry.get("id"))


def remove_selected():
    reset_timer()
    entry = get_selected_entry()
    if not entry:
        messagebox.showwarning("No Selection", "Select an entry from the list first.")
        return
    if not messagebox.askyesno("Confirm Delete",
            f"Delete entry for '{entry['site']}'?"):
        return
    vault.remove_entry_by_id(entry.get("id"))
    refresh_category_menu()
    refresh_display(ent_search.get().strip(), category_var.get(), _reveal_active)


def get_selected_entry() -> dict | None:
    """Detect which entry the cursor is on in the display box."""
    try:
        cursor_line = display_box.index(tk.INSERT).split(".")[0]
        content = display_box.get("1.0", tk.END)
        lines = content.split("\n")
        line_num = int(cursor_line) - 1

        # Walk backwards to find the ID line
        for i in range(line_num, max(line_num - 5, -1), -1):
            if i < len(lines) and lines[i].strip().startswith("ID  :"):
                eid = lines[i].split(":", 1)[1].strip()
                for e in vault.entries:
                    if e.get("id") == eid:
                        return e
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Reveal
# ---------------------------------------------------------------------------

def reveal_selected():
    global _reveal_active
    reset_timer()
    query = ent_search.get().strip()
    if not query and not vault.entries:
        return

    confirm = simpledialog.askstring(
        "Verify Master Password",
        "Enter master password to reveal passwords:", show="*")
    if confirm is None:
        return

    try:
        vault.load(confirm)
    except (ValueError, FileNotFoundError):
        messagebox.showerror("Access Denied", "Incorrect master password.")
        return

    _reveal_active = True
    refresh_display(query, category_var.get(), reveal=True)

    # Auto-hide after clipboard clear interval
    root.after(CLIPBOARD_MS, hide_revealed)


def hide_revealed():
    global _reveal_active
    _reveal_active = False
    refresh_display(ent_search.get().strip(), category_var.get(), reveal=False)


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

def copy_password():
    """Copy password of the entry the cursor is in."""
    reset_timer()
    entry = get_selected_entry()
    if not entry:
        messagebox.showwarning("No Selection", "Place cursor on an entry first.")
        return
    root.clipboard_clear()
    root.clipboard_append(entry["pass"])
    messagebox.showinfo("Copied",
        f"Password for '{entry['site']}' copied.\nClipboard clears in {CLIPBOARD_MS//1000}s.")
    root.after(CLIPBOARD_MS, root.clipboard_clear)


def copy_username():
    reset_timer()
    entry = get_selected_entry()
    if not entry:
        messagebox.showwarning("No Selection", "Place cursor on an entry first.")
        return
    root.clipboard_clear()
    root.clipboard_append(entry["user"])
    messagebox.showinfo("Copied", f"Username for '{entry['site']}' copied.")
    root.after(CLIPBOARD_MS, root.clipboard_clear)


# ---------------------------------------------------------------------------
# Password Generator standalone dialog
# ---------------------------------------------------------------------------

def open_generator():
    dialog = tk.Toplevel(root)
    dialog.title("Password Generator")
    dialog.geometry("400x320")
    dialog.config(bg=DARK["bg"])
    dialog.grab_set()

    tk.Label(dialog, text="Password Generator", bg=DARK["bg"],
             fg=DARK["text"], font=DARK["title"]).pack(pady=(16,8))

    length_var = tk.IntVar(value=CFG["default_password_length"])
    upper_var  = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    sym_var    = tk.BooleanVar(value=True)

    frm = tk.Frame(dialog, bg=DARK["bg"])
    frm.pack(padx=20)

    tk.Label(frm, text="Length:", bg=DARK["bg"], fg=DARK["subtext"],
             font=DARK["ui"]).grid(row=0, column=0, sticky="w", pady=4)
    tk.Scale(frm, from_=8, to=64, orient=tk.HORIZONTAL, variable=length_var,
             bg=DARK["bg"], fg=DARK["text"], highlightthickness=0,
             troughcolor=DARK["surface2"], length=200).grid(row=0, column=1)

    for i, (txt, var) in enumerate([
        ("Uppercase letters", upper_var),
        ("Digits", digits_var),
        ("Symbols", sym_var),
    ], 1):
        tk.Checkbutton(frm, text=txt, variable=var, bg=DARK["bg"],
                       fg=DARK["text"], selectcolor=DARK["surface"],
                       activebackground=DARK["bg"],
                       font=DARK["ui"]).grid(row=i, column=0, columnspan=2, sticky="w")

    result_var = tk.StringVar()
    ent_result = tk.Entry(dialog, textvariable=result_var, bg=DARK["entry_bg"],
                          fg=DARK["accent"], font=("Courier New", 13),
                          relief=tk.FLAT, width=34, justify="center")
    ent_result.pack(pady=10, ipady=6)

    strength_lbl = tk.Label(dialog, text="", bg=DARK["bg"], fg=DARK["warn"],
                             font=DARK["ui"])
    strength_lbl.pack()

    def gen():
        pw = generate_password(
            length_var.get(), upper_var.get(), digits_var.get(), sym_var.get())
        result_var.set(pw)
        score, label = password_strength(pw)
        strength_lbl.config(text=f"Strength: {label}", fg=STRENGTH_COLORS[score])

    def copy():
        root.clipboard_clear()
        root.clipboard_append(result_var.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")
        root.after(CLIPBOARD_MS, root.clipboard_clear)

    btn_row = tk.Frame(dialog, bg=DARK["bg"])
    btn_row.pack()
    tk.Button(btn_row, text="⚡ Generate", command=gen,
              bg=DARK["accent"], fg="white", relief=tk.FLAT,
              font=DARK["ui_bold"], padx=12, pady=4).pack(side=tk.LEFT, padx=6)
    tk.Button(btn_row, text="📋 Copy", command=copy,
              bg=DARK["surface2"], fg="white", relief=tk.FLAT,
              font=DARK["ui"], padx=12, pady=4).pack(side=tk.LEFT, padx=6)
    gen()


# ---------------------------------------------------------------------------
# Change master password
# ---------------------------------------------------------------------------

def change_master_password():
    reset_timer()
    old = simpledialog.askstring("Change Master Password",
        "Enter CURRENT master password:", show="*")
    if old is None:
        return
    new = simpledialog.askstring("Change Master Password",
        "Enter NEW master password (min 10 chars):", show="*")
    if new is None:
        return
    if len(new) < 10:
        messagebox.showwarning("Too Short", "New password must be at least 10 characters.")
        return
    confirm = simpledialog.askstring("Change Master Password",
        "Confirm new master password:", show="*")
    if new != confirm:
        messagebox.showerror("Mismatch", "New passwords do not match.")
        return
    try:
        vault.change_master_password(old, new)
        messagebox.showinfo("Success", "Master password changed successfully.")
    except ValueError as e:
        messagebox.showerror("Error", str(e))


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

def export_vault():
    reset_timer()
    fmt = messagebox.askquestion("Export Format", "Export as JSON? (No = CSV)")
    pw = simpledialog.askstring("Confirm Password",
        "Enter master password to authorize export:", show="*")
    if pw is None:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".json" if fmt == "yes" else ".csv",
        filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All", "*.*")]
    )
    if not path:
        return
    try:
        if fmt == "yes":
            vault.export_json(Path(path), pw)
        else:
            vault.export_csv(Path(path), pw)
        messagebox.showinfo("Exported", f"Vault exported to:\n{path}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", f"Export failed:\n{e}")


def import_vault():
    reset_timer()
    path = filedialog.askopenfilename(
        filetypes=[("JSON", "*.json"), ("All", "*.*")]
    )
    if not path:
        return
    if not messagebox.askyesno("Confirm Import",
            "This will merge entries from the selected file into your vault. Continue?"):
        return
    try:
        added = vault.import_json(Path(path))
        messagebox.showinfo("Imported", f"{added} new entries imported.")
        refresh_category_menu()
        refresh_display()
    except Exception as e:
        messagebox.showerror("Error", f"Import failed:\n{e}")


# ---------------------------------------------------------------------------
# Auto-lock
# ---------------------------------------------------------------------------

def auto_lock_check():
    if vault_frame.winfo_ismapped():
        if time.time() - last_activity > LOCK_TIMEOUT:
            lock_vault()
            messagebox.showwarning("Session Locked",
                "Vault locked due to inactivity.")
    root.after(5000, auto_lock_check)


# ---------------------------------------------------------------------------
# Keyboard shortcuts
# ---------------------------------------------------------------------------

def bind_shortcuts():
    root.bind("<Control-l>", lambda e: lock_vault())
    root.bind("<Control-f>", lambda e: ent_search.focus_set())
    root.bind("<Control-n>", lambda e: add_password())
    root.bind("<Control-g>", lambda e: open_generator())


# ---------------------------------------------------------------------------
# Build UI
# ---------------------------------------------------------------------------

root = tk.Tk()
root.title("🛡️ Encrypted Password Vault")
root.geometry("900x680")
root.config(bg=DARK["bg"])
root.option_add("*Font", DARK["ui"])

# ── Login Frame ─────────────────────────────────────────────────────────────
login_frame = tk.Frame(root, bg=DARK["bg"])
login_frame.pack(pady=100)

tk.Label(login_frame, text="🛡️ Password Vault", bg=DARK["bg"],
         fg=DARK["text"], font=("Segoe UI", 20, "bold")).pack(pady=(0,4))
tk.Label(login_frame, text="Enter your master password to unlock",
         bg=DARK["bg"], fg=DARK["subtext"], font=DARK["ui"]).pack(pady=(0,16))

ent_master = tk.Entry(login_frame, show="*", width=32,
                      bg=DARK["entry_bg"], fg=DARK["text"],
                      insertbackground=DARK["text"],
                      relief=tk.FLAT, font=("Courier New", 13),
                      justify="center")
ent_master.pack(ipady=8)
ent_master.bind("<Return>", check_login)
ent_master.focus_set()

tk.Button(login_frame, text="Unlock Vault", command=check_login,
          bg=DARK["accent"], fg="white", relief=tk.FLAT,
          font=DARK["ui_bold"], padx=30, pady=8,
          cursor="hand2").pack(pady=14)

# ── Vault Frame ──────────────────────────────────────────────────────────────
vault_frame = tk.Frame(root, bg=DARK["bg"])

# Top bar
top_bar = tk.Frame(vault_frame, bg=DARK["bg"])
top_bar.pack(fill=tk.X, pady=(0,8))

tk.Label(top_bar, text="🛡️ Password Vault", bg=DARK["bg"],
         fg=DARK["text"], font=DARK["title"]).pack(side=tk.LEFT)

# Menubar-style buttons (top right)
menu_frame = tk.Frame(top_bar, bg=DARK["bg"])
menu_frame.pack(side=tk.RIGHT)
for txt, cmd, color in [
    ("⚙ Change Password", change_master_password, DARK["subtext"]),
    ("📤 Export", export_vault, DARK["subtext"]),
    ("📥 Import", import_vault, DARK["subtext"]),
    ("🔒 Lock", lock_vault, DARK["danger"]),
]:
    tk.Button(menu_frame, text=txt, command=cmd, bg=DARK["bg"],
              fg=color, relief=tk.FLAT, font=DARK["ui"],
              cursor="hand2", padx=6).pack(side=tk.LEFT, padx=2)

# Search row
search_row = tk.Frame(vault_frame, bg=DARK["bg"])
search_row.pack(fill=tk.X, pady=4)

tk.Label(search_row, text="Search:", bg=DARK["bg"],
         fg=DARK["subtext"], font=DARK["ui"]).pack(side=tk.LEFT)

ent_search = tk.Entry(search_row, width=40, bg=DARK["entry_bg"],
                      fg=DARK["text"], insertbackground=DARK["text"],
                      relief=tk.FLAT, font=DARK["mono"])
ent_search.pack(side=tk.LEFT, padx=6, ipady=4)
ent_search.bind("<KeyRelease>", do_search)

# Category filter
category_var = tk.StringVar(value="All")
tk.Label(search_row, text="Category:", bg=DARK["bg"],
         fg=DARK["subtext"], font=DARK["ui"]).pack(side=tk.LEFT, padx=(10,0))
category_menu = tk.OptionMenu(search_row, category_var, "All")
category_menu.config(bg=DARK["entry_bg"], fg=DARK["text"],
                     relief=tk.FLAT, font=DARK["ui"], padx=4,
                     activebackground=DARK["surface2"],
                     highlightthickness=0)
category_menu["menu"].config(bg=DARK["surface2"], fg=DARK["text"])
category_menu.pack(side=tk.LEFT, padx=4)

# Action buttons
btn_row = tk.Frame(vault_frame, bg=DARK["bg"])
btn_row.pack(fill=tk.X, pady=6)

buttons = [
    ("➕ Add",       add_password,    DARK["success"]),
    ("✏️ Edit",      edit_selected,   DARK["accent"]),
    ("🗑 Remove",    remove_selected, DARK["danger"]),
    ("🔍 Reveal",    reveal_selected, DARK["warn"]),
    ("📋 Copy Pass", copy_password,   DARK["surface2"]),
    ("👤 Copy User", copy_username,   DARK["surface2"]),
    ("⚡ Generator", open_generator,  DARK["accent2"]),
]

for txt, cmd, color in buttons:
    tk.Button(btn_row, text=txt, command=cmd,
              bg=color, fg="white", relief=tk.FLAT,
              font=DARK["ui"], padx=10, pady=5,
              cursor="hand2").pack(side=tk.LEFT, padx=3)

# Shortcut hint
tk.Label(vault_frame,
         text="Ctrl+N: Add  |  Ctrl+F: Search  |  Ctrl+L: Lock  |  Ctrl+G: Generator",
         bg=DARK["bg"], fg=DARK["subtext"], font=("Segoe UI", 8)).pack(anchor="w")

# Display box
display_frame = tk.Frame(vault_frame, bg=DARK["border"], pady=1, padx=1)
display_frame.pack(fill=tk.BOTH, expand=True, pady=8)

display_box = tk.Text(display_frame, bg=DARK["surface"], fg=DARK["text"],
                      font=("Courier New", 10), relief=tk.FLAT,
                      insertbackground=DARK["text"],
                      selectbackground=DARK["accent"],
                      state=tk.DISABLED, cursor="arrow")
scroll = tk.Scrollbar(display_frame, command=display_box.yview,
                      bg=DARK["surface2"])
display_box.config(yscrollcommand=scroll.set)
scroll.pack(side=tk.RIGHT, fill=tk.Y)
display_box.pack(fill=tk.BOTH, expand=True)

# Status bar
status_var = tk.StringVar(value="")
tk.Label(vault_frame, textvariable=status_var, bg=DARK["bg"],
         fg=DARK["subtext"], font=("Segoe UI", 8)).pack(anchor="w")

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

bind_shortcuts()

if not ensure_vault():
    root.destroy()
else:
    auto_lock_check()
    root.mainloop()
