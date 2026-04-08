import tkinter as tk
from tkinter import messagebox, simpledialog
import time

# --- 1. DATA & CONFIG ---
master_pass = ""
second_pass = ""
bypass_key = ""  # <--- NEW: Enter this in Master field to bypass Secondary

password_list = [
    {"site": "club", "user": "sdfghj", "pass": "club_pass_123"},
    {"site": "Banking", "user": "admin_main", "pass": "money_saver_99"},
    {"site": "Gaming", "user": "ProGamer", "pass": "level_up_pass"},
    {"site": "Social", "user": "@cool_user", "pass": "social_shield_22"}
]

is_revealed = False
all_shown = False 
failed_attempts = 0
last_activity = time.time()

# --- 2. LOGIC FUNCTIONS ---

def reset_timer():
    global last_activity
    last_activity = time.time()

def auto_lock_check():
    if vault_frame.winfo_viewable(): 
        if time.time() - last_activity > 120: 
            lock_vault()
            messagebox.showwarning("Session Timeout", "Vault locked due to inactivity.")
    root.after(5000, auto_lock_check)

def check_login(event=None): 
    global failed_attempts
    m_input = ent_master.get()
    s_input = ent_second.get()

    # OPTION 1: Standard Login (Both passwords match)
    if m_input == master_pass and s_input == second_pass:
        login_success()
    
    # OPTION 2: Quick Access (Bypass key used in master field)
    elif m_input == bypass_key:
        messagebox.showinfo("Quick Access", "Logged in via Bypass Key (No secondary needed).")
        login_success()
        
    else:
        failed_attempts += 1
        if failed_attempts >= 3:
            messagebox.showerror("Locked", "Too many failed attempts. Wait 30 seconds.")
            btn_unlock.config(state=tk.DISABLED)
            root.after(30000, lambda: btn_unlock.config(state=tk.NORMAL))
            failed_attempts = 0
        else:
            messagebox.showerror("Denied", f"Incorrect Credentials. ({failed_attempts}/3)")

def login_success():
    """Helper to transition to the vault"""
    global failed_attempts
    failed_attempts = 0
    ent_master.delete(0, tk.END)
    ent_second.delete(0, tk.END)
    login_frame.pack_forget()
    vault_frame.pack(pady=20)
    reset_timer()

def add_password():
    reset_timer()
    site = simpledialog.askstring("Add Entry", "Enter Website Name:")
    if not site: return
    user = simpledialog.askstring("Add Entry", f"Enter Username for {site}:")
    if not user: return
    pw = simpledialog.askstring("Add Entry", f"Enter Password for {site}:", show='*')
    if not pw: return

    password_list.append({"site": site, "user": user, "pass": pw})
    messagebox.showinfo("Success", f"Entry for {site} added!")
    if all_shown: refresh_display()

def remove_password():
    reset_timer()
    query = ent_search.get().lower()
    if not query:
        messagebox.showwarning("Warning", "Type the Website name in the search box to delete it.")
        return
    
    global password_list
    original_count = len(password_list)
    password_list = [item for item in password_list if item['site'].lower() != query]
    
    if len(password_list) < original_count:
        messagebox.showinfo("Deleted", f"Entry for '{query}' removed.")
        clear_search()
        if all_shown: refresh_display()
    else:
        messagebox.showerror("Error", f"No entry found for '{query}'.")

def copy_to_clipboard():
    try:
        selected_text = display_box.get(tk.SEL_FIRST, tk.SEL_LAST)
        root.clipboard_clear()
        root.clipboard_append(selected_text)
        messagebox.showinfo("Clipboard", "Text copied! Will clear in 15 seconds.")
        root.after(15000, lambda: root.clipboard_clear())
        reset_timer()
    except tk.TclError:
        messagebox.showwarning("Warning", "Highlight the text you want to copy first!")

def clear_search():
    global is_revealed, all_shown
    ent_search.delete(0, tk.END)
    display_box.delete(1.0, tk.END)
    is_revealed = False
    all_shown = False
    btn_reveal.config(text="👁 Reveal", bg="#f0ad4e")
    btn_show_all.config(text="Show All", bg="SystemButtonFace")
    reset_timer()

def lock_vault():
    clear_search()
    vault_frame.pack_forget()
    login_frame.pack(pady=70)

def search_data(event=None): 
    global is_revealed
    query = ent_search.get().lower()
    display_box.delete(1.0, tk.END)
    is_revealed = False
    btn_reveal.config(text="👁 Reveal", bg="#f0ad4e")
    reset_timer()
    
    if not query: return 

    for item in password_list:
        if query in item['site'].lower() or query in item['user'].lower():
            result = f"SITE: {item['site']} | USER: {item['user']} | PASS: ********\n"
            display_box.insert(tk.END, result)

def toggle_reveal():
    global is_revealed
    reset_timer()
    if is_revealed:
        search_data()
    else:
        reveal_passwords()

def reveal_passwords():
    global is_revealed
    query = ent_search.get().lower()
    if not query:
        messagebox.showinfo("Note", "Search for something first to reveal it.")
        return
        
    display_box.delete(1.0, tk.END)
    for item in password_list:
        if query in item['site'].lower() or query in item['user'].lower():
            result = f"SITE: {item['site']} | USER: {item['user']} | PASS: {item['pass']}\n"
            display_box.insert(tk.END, result)
    
    is_revealed = True
    btn_reveal.config(text="🙈 Hide", bg="#d9534f")

def toggle_show_all():
    global all_shown
    reset_timer()
    
    if all_shown:
        display_box.delete(1.0, tk.END)
        btn_show_all.config(text="Show All", bg="SystemButtonFace")
        all_shown = False
    else:
        verify = simpledialog.askstring("Security Check", "Enter Master Password to show all:", show='*')
        if verify == master_pass or verify == bypass_key:
            refresh_display()
            btn_show_all.config(text="Hide All", bg="#d9534f")
            all_shown = True
        elif verify is not None:
            messagebox.showerror("Error", "Incorrect Password")

def refresh_display():
    display_box.delete(1.0, tk.END)
    for item in password_list:
        display_box.insert(tk.END, f"SITE: {item['site']} | USER: {item['user']} | PASS: {item['pass']}\n")

# --- 3. UI SETUP ---
root = tk.Tk()
root.title("🛡️ Secure Password Carrier")
root.geometry("750x650")

# --- LOGIN SCREEN ---
login_frame = tk.Frame(root)
login_frame.pack(pady=70)

tk.Label(login_frame, text="Master Password").pack()
ent_master = tk.Entry(login_frame, show="*")
ent_master.pack()

tk.Label(login_frame, text="Secondary Key").pack()
ent_second = tk.Entry(login_frame, show="*")
ent_second.pack()

ent_master.bind('<Return>', check_login)
ent_second.bind('<Return>', check_login)

btn_unlock = tk.Button(login_frame, text="Unlock Vault", command=check_login, bg="green", fg="white")
btn_unlock.pack(pady=10)

# --- VAULT SCREEN ---
vault_frame = tk.Frame(root)

tk.Label(vault_frame, text="Search Site/Email:").pack()
ent_search = tk.Entry(vault_frame)
ent_search.pack()
ent_search.bind('<Return>', search_data)

btn_group = tk.Frame(vault_frame)
btn_group.pack(pady=5)

tk.Button(btn_group, text="Search", command=search_data).pack(side=tk.LEFT, padx=2)
btn_reveal = tk.Button(btn_group, text="👁 Reveal", command=toggle_reveal, bg="#f0ad4e")
btn_reveal.pack(side=tk.LEFT, padx=2)

btn_show_all = tk.Button(btn_group, text="Show All", command=toggle_show_all)
btn_show_all.pack(side=tk.LEFT, padx=2)

tk.Button(btn_group, text="➕ Add", command=add_password, bg="#5cb85c", fg="white").pack(side=tk.LEFT, padx=2)
tk.Button(btn_group, text="🗑️ Remove", command=remove_password, bg="#d9534f", fg="white").pack(side=tk.LEFT, padx=2)
tk.Button(btn_group, text="📋 Copy", command=copy_to_clipboard).pack(side=tk.LEFT, padx=2)
tk.Button(btn_group, text="Clear", command=clear_search).pack(side=tk.LEFT, padx=2)
tk.Button(btn_group, text="🔒 Lock", command=lock_vault, bg="red", fg="white").pack(side=tk.LEFT, padx=2)

display_box = tk.Text(vault_frame, height=15, width=90)
display_box.pack(pady=10)

auto_lock_check()
root.mainloop()