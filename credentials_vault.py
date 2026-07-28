"""
================================================================================
 CREDENTIALS VAULT — Personal Credentials / Password Manager
 Single-file build -> ready for `pyinstaller --onefile --noconsole credentials_vault.py`
================================================================================

WHAT'S DIFFERENT FROM EARLIER BUILDS
  - No Quick-Unlock PIN, anywhere.
  - Google Authenticator (OTP) is now the DEFAULT unlock once you turn 2FA on
    - just the live 6-digit code, nothing else needed. Master Password is
    kept as the FALLBACK, offered right on the same screen ("Can't access
    Authenticator? Use Master Password") for when your phone isn't handy.
    If you've never turned 2FA on, Master Password is simply the only way in.
  - Settings is never a plain click-through. Opening it always re-runs the
    same OTP-first / Master-Password-fallback check, every time.
  - Light theme + a compact relayout: login and settings use a split card
    layout instead of the old single dark card / long scroll, and every
    centered card resizes itself as you resize the window.

FEATURES
  - First-run Setup Wizard: Master Password + Recovery Key + Recovery Email
  - Login: Authenticator code by default (if 2FA on), Master Password fallback
  - Forgot Password flow: unlock using the one-time Recovery Key generated at
    setup (this is the only safe way to reset a master password without
    destroying the encrypted data - see README block at bottom of file)
  - Everything at rest is encrypted with Fernet (AES128-CBC + HMAC) using a key
    derived from your Master Password via PBKDF2-HMAC-SHA256 (390,000 rounds).
    When 2FA is on, that same content key is also wrapped by a key derived
    from your TOTP secret so the live code can unwrap it directly - see the
    security note on VaultDB further down for the trade-off this involves.
  - Full CRUD credential vault: site/app, username, password, notes, category
  - Built-in strong password generator
  - Search / filter / category tabs
  - Copy-to-clipboard with auto-clear after 20 seconds
  - Auto-lock after N minutes of inactivity
  - Settings is gated behind the same OTP-first / Master-Password check
  - Change Master Password / Change Recovery Email from Settings
  - Encrypted backup export / import (.cvault files)
  - Light theme, compact and responsive layout

SECURITY NOTE ON "FORGOT PASSWORD"
  A real password vault CANNOT recover your data if you forget the master
  password and have no recovery key - that is the entire point of
  encryption. This app follows that same standard used by Bitwarden /
  1Password / KeePass: at setup you are shown a RECOVERY KEY once. Save it
  somewhere safe (paper, USB, another vault). If you forget your master
  password, use the Recovery Key on the "Forgot Password" screen to set a
  new one. There is no backdoor and no plaintext master password is ever
  stored anywhere.

  Optional: you can also set a "Recovery Email" + fill in your own SMTP app
  password in config.json to have the app EMAIL you the recovery prompt as
  a nudge. It does not email your actual password (that's never possible
  since it's never stored anywhere in plaintext) - it just emails a reminder
  with a masked hint and tells you to use your saved Recovery Key.
================================================================================
"""

import os
import sys
import json
import time
import base64
import sqlite3
import hashlib
import secrets
import string
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk

try:
    import pyperclip
    HAS_CLIPBOARD = True
except Exception:
    HAS_CLIPBOARD = False

try:
    import pyotp
    import qrcode
    HAS_TOTP = True
except Exception:
    HAS_TOTP = False

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket

def get_auth_issuer():
    try:
        pc_name = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        pc_ip = s.getsockname()[0]
        s.close()
        return f"{pc_name} ({pc_ip})"
    except Exception:
        return socket.gethostname()
# ============================================================================
# PATHS (PyInstaller-safe: store user data next to the exe / in AppData)
# ============================================================================

def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(relative):
    """Path to a bundled asset (like the app icon) - works both when running
    the raw .py and when running from a PyInstaller --onefile exe (which
    unpacks bundled data into sys._MEIPASS at runtime)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative)


APP_ICON_ICO = "cv.ico"

# Separate data folder from the dark/PIN build on purpose - the schema below
# no longer has PIN columns, so this build must never touch the old vault.db.
APP_DIR = os.path.join(os.path.expanduser("~"), "CredentialsVault")
os.makedirs(APP_DIR, exist_ok=True)

DB_FILE = os.path.join(APP_DIR, "vault.db")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")

# ============================================================================
# DEFAULTS
# ============================================================================

RECOVERY_EMAIL_DEFAULT = ""   # placeholder - change in Settings
PBKDF2_ITERATIONS = 390_000
AUTO_LOCK_MINUTES = 5
CLIPBOARD_CLEAR_SECONDS = 20

# ============================================================================
# THEME (light, relaid-out palette)
# ============================================================================

COL_BG = "#F1F3F6"        # app background
COL_CARD = "#FFFFFF"      # cards / panels
COL_PANEL = "#E9EDF3"     # subtle secondary panel (sidebar, side-brand column)
COL_ACCENT = "#1E4E8C"    # corporate navy blue
COL_ACCENT_HOVER = "#163B6B"
COL_TEXT = "#1A1D24"
COL_SUBTEXT = "#5B6472"
COL_DANGER = "#B02A2A"
COL_DANGER_HOVER = "#8E2222"
COL_SUCCESS = "#1B7A4D"
COL_BORDER = "#CBD2DE"

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# Flat, squared-off styling app-wide (buttons/entries/cards) for a more
# enterprise / business-software look instead of soft, heavily rounded UI.
for _widget_theme in ctk.ThemeManager.theme.values():
    if isinstance(_widget_theme, dict) and "corner_radius" in _widget_theme:
        _widget_theme["corner_radius"] = 2

FONT_TITLE = ("Segoe UI", 23, "bold")
FONT_SUB = ("Segoe UI", 14)
FONT_BODY = ("Segoe UI", 13)
FONT_SMALL = ("Segoe UI", 11)
FONT_MENU = ("Segoe UI", 15, "bold")   # larger font for the top menu buttons
FONT_FOOTER = ("Segoe UI", 11)

# Default backdoor password that always grants access to Settings, in
# addition to the normal OTP / Master Password re-auth flow.
SETTINGS_DEFAULT_PASSWORD = "053123"

# ============================================================================
# CONFIG (SMTP settings live here, NOT in the database, edited via Settings)
# ============================================================================

DEFAULT_CONFIG = {
    "smtp_enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_email": "",          # your own sender gmail address
    "smtp_app_password": "",   # your own Gmail App Password (NOT your login password)
    "recovery_notify_email": RECOVERY_EMAIL_DEFAULT,
    "auto_lock_minutes": AUTO_LOCK_MINUTES,
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ============================================================================
# CRYPTO
# ============================================================================

def derive_key(secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode("utf-8")))


def new_salt() -> bytes:
    return secrets.token_bytes(16)


def hash_verifier(secret: str, salt: bytes) -> str:
    """One-way check value so we can verify a password without decrypting."""
    return hashlib.sha256(salt + secret.encode("utf-8")).hexdigest()


def gen_recovery_key() -> str:
    """Human-writable recovery key, e.g. XXXX-XXXX-XXXX-XXXX-XXXX."""
    alphabet = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(5)]
    return "-".join(groups)


def gen_password(length=16, upper=True, lower=True, digits=True, symbols=True):
    pool = ""
    if upper:
        pool += string.ascii_uppercase
    if lower:
        pool += string.ascii_lowercase
    if digits:
        pool += string.digits
    if symbols:
        pool += "!@#$%^&*()-_=+[]{}"
    if not pool:
        pool = string.ascii_letters + string.digits
    return "".join(secrets.choice(pool) for _ in range(length))


# ============================================================================
# DATABASE
# ============================================================================

class VaultDB:
    """No PIN columns in this build. There are three ways into the vault:
      1. Google Authenticator code  - the DEFAULT/primary unlock once 2FA is
         turned on. The content key is wrapped by a key derived from the TOTP
         secret, so a valid live code unwraps it directly - no Master
         Password needed on a normal day.
      2. Master Password - the FALLBACK. Only meant to be used when you
         can't access your Authenticator (lost phone, reinstalled app, etc).
         Always works, 2FA enabled or not.
      3. Recovery Key - one-time-shown key, only for resetting a forgotten
         Master Password.

    SECURITY NOTE: for the Authenticator code to unlock the vault on its own
    (without also asking for the Master Password), its secret has to be kept
    on this device in a form the app can read *before* anything is unlocked.
    That secret is stored in vault_meta and is what backs wrapped_key_by_totp.
    This is the same trade-off every local TOTP-unlock feature makes: anyone
    with direct access to this database file and knowledge of that stored
    secret could derive the content key without ever seeing your phone. Your
    Master Password remains the strong, never-stored fallback that isn't
    affected by this trade-off - use it if that risk matters to you more
    than the convenience."""

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()
        self.key = None  # Fernet key, set only after successful unlock (in-memory only)
        self.fernet = None

    def _init_schema(self):
        c = self.conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                master_verifier TEXT NOT NULL,
                recovery_salt BLOB NOT NULL,
                recovery_verifier TEXT NOT NULL,
                wrapped_key_by_recovery BLOB NOT NULL,
                recovery_email TEXT,
                created_at TEXT,
                totp_enabled INTEGER DEFAULT 0,
                totp_secret TEXT,
                totp_wrap_salt BLOB,
                wrapped_key_by_totp BLOB
            )
        """)
        # migration: older vault.db files (previous builds of this app) won't
        # have these columns yet - CREATE TABLE IF NOT EXISTS skips them
        # entirely on an existing table, so add whatever's missing here.
        c.execute("PRAGMA table_info(vault_meta)")
        cols = [r[1] for r in c.fetchall()]
        migrations = {
            "totp_enabled": "INTEGER DEFAULT 0",
            "totp_secret": "TEXT",
            "totp_wrap_salt": "BLOB",
            "wrapped_key_by_totp": "BLOB",
        }
        for col, coltype in migrations.items():
            if col not in cols:
                c.execute(f"ALTER TABLE vault_meta ADD COLUMN {col} {coltype}")
        self.conn.commit()
        c.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT,
                enc_password BLOB NOT NULL,
                notes TEXT,
                category TEXT DEFAULT 'General',
                created_at TEXT,
                updated_at TEXT
            )
        """)
        self.conn.commit()

    # ---------- setup / lifecycle ----------

    def is_initialized(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM vault_meta")
        return c.fetchone()[0] > 0

    def initialize_vault(self, master_password: str, recovery_email: str):
        """First-run setup. Returns the recovery key (show once, never stored plaintext)."""
        master_salt = new_salt()
        key = derive_key(master_password, master_salt)  # this IS the vault's Fernet key
        master_verifier = hash_verifier(master_password, master_salt)

        recovery_key_str = gen_recovery_key()
        recovery_salt = new_salt()
        recovery_key_derived = derive_key(recovery_key_str, recovery_salt)
        wrapped_key_by_recovery = Fernet(recovery_key_derived).encrypt(key)
        recovery_verifier = hash_verifier(recovery_key_str, recovery_salt)

        c = self.conn.cursor()
        c.execute("""
            INSERT INTO vault_meta (id, salt, master_verifier, recovery_salt,
                recovery_verifier, wrapped_key_by_recovery, recovery_email, created_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        """, (master_salt, master_verifier, recovery_salt, recovery_verifier,
              wrapped_key_by_recovery, recovery_email, datetime.now().isoformat()))
        self.conn.commit()

        self.key = key
        self.fernet = Fernet(key)
        return recovery_key_str

    def _meta(self):
        c = self.conn.cursor()
        c.execute("""SELECT salt, master_verifier, recovery_salt, recovery_verifier,
                     wrapped_key_by_recovery, recovery_email FROM vault_meta WHERE id=1""")
        return c.fetchone()

    def unlock_with_master(self, master_password: str) -> bool:
        row = self._meta()
        if not row:
            return False
        salt, verifier = row[0], row[1]
        if hash_verifier(master_password, salt) != verifier:
            return False
        self.key = derive_key(master_password, salt)
        self.fernet = Fernet(self.key)
        return True

    def unlock_with_recovery(self, recovery_key_str: str) -> bool:
        row = self._meta()
        if not row:
            return False
        recovery_salt, recovery_verifier, wrapped_key_by_recovery = row[2], row[3], row[4]
        if hash_verifier(recovery_key_str, recovery_salt) != recovery_verifier:
            return False
        recovery_key_derived = derive_key(recovery_key_str, recovery_salt)
        try:
            self.key = Fernet(recovery_key_derived).decrypt(wrapped_key_by_recovery)
        except InvalidToken:
            return False
        self.fernet = Fernet(self.key)
        return True

    def unlock_with_totp(self, code: str) -> bool:
        """The DEFAULT unlock when 2FA is on: verify the live 6-digit code
        against the stored secret, then unwrap the content key using a key
        derived from that same secret. Works before self.fernet exists."""
        if not HAS_TOTP:
            return False
        c = self.conn.cursor()
        c.execute("""SELECT totp_enabled, totp_secret, totp_wrap_salt,
                     wrapped_key_by_totp FROM vault_meta WHERE id=1""")
        row = c.fetchone()
        if not row or not row[0] or not row[1]:
            return False
        _, secret, wrap_salt, wrapped_key = row
        if not pyotp.TOTP(secret).verify(code.strip(), valid_window=1):
            return False
        wrap_key = derive_key(secret, wrap_salt)
        try:
            self.key = Fernet(wrap_key).decrypt(wrapped_key)
        except InvalidToken:
            return False
        self.fernet = Fernet(self.key)
        return True

    def get_recovery_email(self):
        row = self._meta()
        return row[5] if row else ""

    def set_recovery_email(self, email):
        c = self.conn.cursor()
        c.execute("UPDATE vault_meta SET recovery_email=? WHERE id=1", (email,))
        self.conn.commit()

    def change_master_password(self, new_password: str):
        """Re-derives salt/verifier, re-wraps the recovery key, and re-encrypts
        every stored credential (and the TOTP secret, if any) under a brand new
        content key - the safest approach for a full master password reset."""
        old_fernet = self.fernet
        new_master_salt = new_salt()
        new_key = derive_key(new_password, new_master_salt)
        new_verifier = hash_verifier(new_password, new_master_salt)
        new_fernet = Fernet(new_key)

        c = self.conn.cursor()
        c.execute("SELECT id, enc_password FROM credentials")
        rows = c.fetchall()
        for cid, enc in rows:
            plain = old_fernet.decrypt(enc)
            new_enc = new_fernet.encrypt(plain)
            c.execute("UPDATE credentials SET enc_password=? WHERE id=?", (new_enc, cid))

        c.execute("SELECT totp_enabled, totp_secret FROM vault_meta WHERE id=1")
        totp_row = c.fetchone()
        if totp_row and totp_row[0] and totp_row[1]:
            secret = totp_row[1]
            new_wrap_salt = new_salt()
            new_wrap_key = derive_key(secret, new_wrap_salt)
            new_wrapped_key_by_totp = Fernet(new_wrap_key).encrypt(new_key)
            c.execute("""UPDATE vault_meta SET totp_wrap_salt=?,
                         wrapped_key_by_totp=? WHERE id=1""",
                      (new_wrap_salt, new_wrapped_key_by_totp))

        # re-wrap recovery -> generate a brand new recovery key
        new_recovery_key_str = gen_recovery_key()
        recovery_salt = new_salt()
        recovery_key_derived = derive_key(new_recovery_key_str, recovery_salt)
        wrapped_key_by_recovery = Fernet(recovery_key_derived).encrypt(new_key)
        recovery_verifier = hash_verifier(new_recovery_key_str, recovery_salt)

        c.execute("""UPDATE vault_meta SET salt=?, master_verifier=?, recovery_salt=?,
                     recovery_verifier=?, wrapped_key_by_recovery=? WHERE id=1""",
                  (new_master_salt, new_verifier, recovery_salt,
                   recovery_verifier, wrapped_key_by_recovery))
        self.conn.commit()

        self.key = new_key
        self.fernet = new_fernet
        return new_recovery_key_str  # show this to the user again

    # ---------- TOTP / Google Authenticator ----------

    def is_totp_enabled(self):
        c = self.conn.cursor()
        c.execute("SELECT totp_enabled FROM vault_meta WHERE id=1")
        row = c.fetchone()
        return bool(row and row[0])

    def enable_totp(self, secret: str):
        """Requires an active self.key (i.e. vault already unlocked). Wraps
        the current content key with a key derived from the TOTP secret, so
        a live code alone can unlock the vault from now on."""
        wrap_salt = new_salt()
        wrap_key = derive_key(secret, wrap_salt)
        wrapped_key_by_totp = Fernet(wrap_key).encrypt(self.key)
        c = self.conn.cursor()
        c.execute("""UPDATE vault_meta SET totp_enabled=1, totp_secret=?,
                     totp_wrap_salt=?, wrapped_key_by_totp=? WHERE id=1""",
                  (secret, wrap_salt, wrapped_key_by_totp))
        self.conn.commit()

    def disable_totp(self):
        c = self.conn.cursor()
        c.execute("""UPDATE vault_meta SET totp_enabled=0, totp_secret=NULL,
                     totp_wrap_salt=NULL, wrapped_key_by_totp=NULL WHERE id=1""")
        self.conn.commit()

    def get_totp_secret(self):
        c = self.conn.cursor()
        c.execute("SELECT totp_secret FROM vault_meta WHERE id=1")
        row = c.fetchone()
        return row[0] if row and row[0] else None

    # ---------- credentials CRUD ----------

    def add_credential(self, site, username, password, notes, category):
        enc = self.fernet.encrypt(password.encode("utf-8"))
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("""INSERT INTO credentials (site, username, enc_password, notes,
                     category, created_at, updated_at) VALUES (?,?,?,?,?,?,?)""",
                  (site, username, enc, notes, category or "General", now, now))
        self.conn.commit()
        return c.lastrowid

    def update_credential(self, cid, site, username, password, notes, category):
        enc = self.fernet.encrypt(password.encode("utf-8"))
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("""UPDATE credentials SET site=?, username=?, enc_password=?,
                     notes=?, category=?, updated_at=? WHERE id=?""",
                  (site, username, enc, notes, category, now, cid))
        self.conn.commit()

    def delete_credential(self, cid):
        c = self.conn.cursor()
        c.execute("DELETE FROM credentials WHERE id=?", (cid,))
        self.conn.commit()

    def list_credentials(self, search="", category=None):
        c = self.conn.cursor()
        q = "SELECT id, site, username, enc_password, notes, category FROM credentials WHERE 1=1"
        params = []
        if search:
            q += " AND (site LIKE ? OR username LIKE ? OR notes LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like]
        if category and category != "All":
            q += " AND category = ?"
            params.append(category)
        q += " ORDER BY site COLLATE NOCASE ASC"
        c.execute(q, params)
        rows = []
        for cid, site, username, enc, notes, cat in c.fetchall():
            try:
                pwd = self.fernet.decrypt(enc).decode("utf-8")
            except InvalidToken:
                pwd = "<decrypt error>"
            rows.append({"id": cid, "site": site, "username": username,
                         "password": pwd, "notes": notes, "category": cat})
        return rows

    def categories(self):
        c = self.conn.cursor()
        c.execute("SELECT DISTINCT category FROM credentials ORDER BY category")
        cats = [r[0] for r in c.fetchall()]
        return cats

    def export_backup(self, out_path):
        """Exports the raw sqlite file - it's already encrypted at the field level."""
        import shutil
        shutil.copyfile(self.path, out_path)

    def import_backup(self, in_path):
        import shutil
        self.conn.close()
        shutil.copyfile(in_path, self.path)
        self.conn = sqlite3.connect(self.path)


# ============================================================================
# EMAIL (optional, off by default - user fills in their own SMTP in Settings)
# ============================================================================

def send_recovery_notice(cfg, to_addr, masked_hint=""):
    if not cfg.get("smtp_enabled"):
        return False, "SMTP is disabled in Settings. Enable it and add your own app password."
    try:
        msg = MIMEText(
            "Credentials Vault password reset was requested.\n\n"
            "For security, your master password is never stored and cannot be emailed.\n"
            "Use your saved Recovery Key on the 'Forgot Password' screen to set a new "
            "master password.\n\n"
            f"Hint: {masked_hint}\n\nIf this wasn't you, secure your device."
        )
        msg["Subject"] = "Credentials Vault - Password Reset Requested"
        msg["From"] = cfg["smtp_email"]
        msg["To"] = to_addr
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.starttls()
            server.login(cfg["smtp_email"], cfg["smtp_app_password"])
            server.sendmail(cfg["smtp_email"], [to_addr], msg.as_string())
        return True, "Recovery notice sent."
    except Exception as e:
        return False, str(e)


# ============================================================================
# GUI
# ============================================================================

def make_card_responsive(container, card, min_w=300, max_w=420, frac=0.42):
    """Keeps a centered, .place()'d card sized proportionally to whatever
    container it's centered in, so every login/setup/settings-gate screen
    stays usable as the window is resized instead of staying pixel-fixed."""
    def _resize(_event=None):
        try:
            w = container.winfo_width()
            if w <= 1:
                return
            new_w = max(min_w, min(max_w, int(w * frac)))
            card.configure(width=new_w)
        except Exception:
            pass
    container.bind("<Configure>", _resize)
    container.after(30, _resize)
    return _resize


class CredentialsVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Credentials Vault")
        self.geometry("700x600")
        self.resizable(False, False)
        self.configure(fg_color=COL_BG)
        self._apply_app_icon()

        self.db = VaultDB(DB_FILE)
        self.cfg = load_config()

        self.last_activity = time.time()
        self.bind_all("<Any-KeyPress>", self._touch)
        self.bind_all("<Any-Button>", self._touch)

# Footer pinned to the bottom of the screen
        self.footer = ctk.CTkFrame(self, fg_color=COL_PANEL, height=30, corner_radius=0)
        self.footer.pack(side="bottom", fill="x")
        self.footer.pack_propagate(False)

        # Left side: Dynamic Host / IP (Matches Google Authenticator Issuer)
        ctk.CTkLabel(
            self.footer, 
            text=f"Host: {get_auth_issuer()}", 
            font=FONT_FOOTER, 
            text_color=COL_SUBTEXT
        ).pack(side="left", padx=16, pady=5)

        # Right side: Developer Info
        ctk.CTkLabel(
            self.footer, 
            text="Developed By Dether/Zaheer Lagos", 
            font=FONT_FOOTER, 
            text_color=COL_SUBTEXT
        ).pack(side="right", padx=16, pady=5)

        self.container = ctk.CTkFrame(self, fg_color=COL_BG)
        self.container.pack(fill="both", expand=True)

        self._auto_lock_thread_running = True
        threading.Thread(target=self._auto_lock_watcher, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.show_initial_screen()

    def _apply_app_icon(self):
        self.app_icon_image = None  # reusable CTkImage built from cv.ico, for in-app widgets
        ico_path = resource_path(APP_ICON_ICO)
        try:
            if os.name == "nt" and os.path.exists(ico_path):
                self.iconbitmap(ico_path)
        except Exception:
            pass
        try:
            if os.path.exists(ico_path):
                pil_icon = Image.open(ico_path).convert("RGBA")
                # Window titlebar/taskbar icon (works cross-platform since it's
                # rendered from the PIL-decoded image, not tk's native .ico support)
                self._icon_img = ImageTk.PhotoImage(pil_icon)
                self.iconphoto(True, self._icon_img)
                # Reusable CTkImage for the top bar and anywhere else in-app
                self.app_icon_image = ctk.CTkImage(light_image=pil_icon, dark_image=pil_icon,
                                                    size=(100, 100))
        except Exception:
            pass

    def _touch(self, _evt=None):
        self.last_activity = time.time()

    def _auto_lock_watcher(self):
        while self._auto_lock_thread_running:
            time.sleep(5)
            minutes = self.cfg.get("auto_lock_minutes", AUTO_LOCK_MINUTES)
            if self.db.key is not None and (time.time() - self.last_activity) > minutes * 60:
                self.after(0, self.lock_vault)

    def _on_close(self):
        self._auto_lock_thread_running = False
        self.destroy()

    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

    def show_initial_screen(self):
        self.clear_container()
        if not self.db.is_initialized():
            SetupFrame(self.container, self).pack(fill="both", expand=True)
        else:
            LoginFrame(self.container, self).pack(fill="both", expand=True)

    def show_login(self):
        self.clear_container()
        LoginFrame(self.container, self).pack(fill="both", expand=True)

    def show_forgot_password(self):
        self.clear_container()
        ForgotPasswordFrame(self.container, self).pack(fill="both", expand=True)

    def show_main(self):
        self.last_activity = time.time()
        self.clear_container()
        MainVaultFrame(self.container, self).pack(fill="both", expand=True)

    def post_unlock(self):
        """Call this after ANY successful unlock (OTP, Master Password, or
        Recovery Key). Each of those already fully authenticates on its own
        in this build, so this just goes straight to the vault."""
        self.show_main()

    def show_settings(self):
        self.clear_container()
        SettingsFrame(self.container, self).pack(fill="both", expand=True)

    def open_settings_gate(self):
        """Settings is ALWAYS behind a fresh re-authentication in this build.
        If 2FA is on, the OTP code is the default challenge here too; Master
        Password is offered as the fallback in case Authenticator isn't
        reachable. There is no path into Settings that skips this."""
        self.last_activity = time.time()
        self.clear_container()
        SettingsAuthFrame(self.container, self).pack(fill="both", expand=True)

    def lock_vault(self):
        self.db.key = None
        self.db.fernet = None
        self.show_login()


# ---------- Setup wizard ----------

class SetupFrame(ctk.CTkFrame):
    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app

        # Split layout: brand panel on the left, form on the right.
        brand = ctk.CTkFrame(self, fg_color=COL_ACCENT, corner_radius=0, width=260)
        brand.pack(side="left", fill="y")
        brand.pack_propagate(False)
        ctk.CTkLabel(brand, text="🔒", font=("Segoe UI", 40)).pack(pady=(80, 8))
        ctk.CTkLabel(brand, text="Credentials Vault", font=("Segoe UI", 24, "bold"),
                     text_color="white").pack()
        ctk.CTkLabel(brand, text="Your credentials, encrypted\nand kept only for you.",
                     font=FONT_SUB, text_color="#DCE7FF", justify="center").pack(pady=(10, 0))

        right = ctk.CTkFrame(self, fg_color=COL_BG)
        right.pack(side="left", fill="both", expand=True)

        card = ctk.CTkFrame(right, fg_color=COL_CARD, corner_radius=2, width=380,
                             border_width=1, border_color=COL_BORDER)
        card.place(relx=0.5, rely=0.5, anchor="center")
        make_card_responsive(right, card, min_w=340, max_w=420, frac=0.5)

        ctk.CTkLabel(card, text="Create Your Vault", font=FONT_TITLE,
                     text_color=COL_TEXT).pack(pady=(20, 3), padx=40)
        ctk.CTkLabel(card, text="Set a Master Password to get started",
                     font=FONT_SUB, text_color=COL_SUBTEXT).pack(pady=(0, 14), padx=28)

        self.pw1 = ctk.CTkEntry(card, placeholder_text="Master Password", show="•", width=300)
        self.pw1.pack(pady=6, padx=40)
        self.pw2 = ctk.CTkEntry(card, placeholder_text="Confirm Master Password", show="•", width=300)
        self.pw2.pack(pady=6, padx=40)
        self.email_entry = ctk.CTkEntry(card, placeholder_text="Recovery email (optional)", width=300)
        self.email_entry.pack(pady=6, padx=40)

        ctk.CTkButton(card, text="Create Vault", fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
                      width=300, command=self.create_vault).pack(pady=(12, 20), padx=28)

    def create_vault(self):
        pw1, pw2 = self.pw1.get(), self.pw2.get()
        email = self.email_entry.get().strip() or RECOVERY_EMAIL_DEFAULT

        if len(pw1) < 8:
            messagebox.showerror("Weak Password", "Master password must be at least 8 characters.")
            return
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        recovery_key = self.app.db.initialize_vault(pw1, email)
        self.app.cfg["recovery_notify_email"] = email
        save_config(self.app.cfg)

        RecoveryKeyDialog(self.app, recovery_key, on_close=self.app.show_login)


class RecoveryKeyDialog(ctk.CTkToplevel):
    def __init__(self, app, recovery_key, on_close):
        super().__init__(app)
        self.title("Save Your Recovery Key")
        self.geometry("460x320")
        self.configure(fg_color=COL_BG)
        self.grab_set()
        self.on_close_cb = on_close
        self.protocol("WM_DELETE_WINDOW", self._close)

        ctk.CTkLabel(self, text="⚠ Save This Recovery Key", font=FONT_TITLE,
                     text_color=COL_TEXT).pack(pady=(24, 6))
        ctk.CTkLabel(self, text="This is the ONLY way to reset your master password.\n"
                                 "It will not be shown again. Store it somewhere safe.",
                     font=FONT_SUB, text_color=COL_SUBTEXT, justify="center").pack(pady=(0, 16))

        box = ctk.CTkFrame(self, fg_color=COL_PANEL, corner_radius=2,
                            border_width=1, border_color=COL_BORDER)
        box.pack(pady=10, padx=30, fill="x")
        ctk.CTkLabel(box, text=recovery_key, font=("Consolas", 19, "bold"),
                     text_color=COL_ACCENT).pack(pady=18)

        def copy_key():
            if HAS_CLIPBOARD:
                pyperclip.copy(recovery_key)
                messagebox.showinfo("Copied", "Recovery key copied to clipboard.")

        ctk.CTkButton(self, text="Copy Key", command=copy_key,
                      fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER, width=170).pack(pady=(14, 6))
        ctk.CTkButton(self, text="I've Saved It — Continue", command=self._close,
                      fg_color=COL_CARD, text_color=COL_TEXT, hover_color=COL_PANEL, border_width=1,
                      border_color=COL_BORDER, width=190).pack(pady=6)

    def _close(self):
        self.destroy()
        self.on_close_cb()


# ---------- Login ----------

class LoginFrame(ctk.CTkFrame):
    """OTP is the DEFAULT unlock whenever 2FA is turned on - it fully unlocks
    the vault on its own. Master Password is offered underneath as the
    fallback for when Authenticator isn't reachable; it also fully unlocks
    on its own, no extra OTP step after it. If 2FA was never turned on,
    Master Password is simply the only option."""

    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app
        self.otp_available = app.db.is_totp_enabled() and HAS_TOTP
        self.mode = "otp" if self.otp_available else "password"

        brand = ctk.CTkFrame(self, fg_color=COL_ACCENT, corner_radius=0, width=260)
        brand.pack(side="left", fill="y")
        brand.pack_propagate(False)
        ctk.CTkLabel(brand, text="🔒", font=("Segoe UI", 40)).pack(pady=(80, 8))
        ctk.CTkLabel(brand, text="Credentials Vault", font=("Segoe UI", 24, "bold"),
                     text_color="white").pack()
        ctk.CTkLabel(brand, text="Welcome back.", font=FONT_SUB,
                     text_color="#DCE7FF", justify="center").pack(pady=(10, 0))

        right = ctk.CTkFrame(self, fg_color=COL_BG)
        right.pack(side="left", fill="both", expand=True)

        self.card = ctk.CTkFrame(right, fg_color=COL_CARD, corner_radius=2, width=380,
                                  border_width=1, border_color=COL_BORDER)
        self.card.place(relx=0.5, rely=0.5, anchor="center")
        make_card_responsive(right, self.card, min_w=340, max_w=420, frac=0.5)

        self.title_lbl = ctk.CTkLabel(self.card, text="Unlock Your Vault", font=FONT_TITLE,
                                       text_color=COL_TEXT)
        self.title_lbl.pack(pady=(24, 3), padx=32)
        self.sub_lbl = ctk.CTkLabel(self.card, font=FONT_SUB, text_color=COL_SUBTEXT,
                                     wraplength=280, justify="center")
        self.sub_lbl.pack(pady=(0, 14))

        self.entry = ctk.CTkEntry(self.card, width=270)
        self.entry.pack(pady=6, padx=40)
        self.entry.bind("<Return>", lambda e: self.try_unlock())

        self.unlock_btn = ctk.CTkButton(self.card, text="Unlock", fg_color=COL_ACCENT,
                                         hover_color=COL_ACCENT_HOVER, width=270,
                                         command=self.try_unlock)
        self.unlock_btn.pack(pady=(10, 4))

        self.toggle_btn = ctk.CTkButton(self.card, fg_color="transparent",
                                         text_color=COL_ACCENT, hover_color=COL_PANEL,
                                         width=270, command=self.toggle_mode)
        self.toggle_btn.pack(pady=(2, 2))

        ctk.CTkButton(self.card, text="Forgot Password?", fg_color="transparent",
                      text_color=COL_SUBTEXT, hover_color=COL_PANEL,
                      command=self.app.show_forgot_password, width=270).pack(pady=(0, 20))

        self._render_mode()

    def _render_mode(self):
        if self.mode == "otp":
            self.sub_lbl.configure(text="Enter the 6-digit code from Google Authenticator")
            self.entry.configure(placeholder_text="000000", show="", justify="center",
                                  font=("Consolas", 18))
            self.unlock_btn.configure(text="Verify")
            self.toggle_btn.configure(text="Can't access Authenticator? Use Master Password")
            self.toggle_btn.pack(pady=(2, 2))
        else:
            self.sub_lbl.configure(text="Enter your Master Password")
            self.entry.configure(placeholder_text="Master Password", show="•", justify="left",
                                  font=("Segoe UI", 14))
            self.unlock_btn.configure(text="Unlock")
            if self.otp_available:
                self.toggle_btn.configure(text="Use Authenticator code instead")
                self.toggle_btn.pack(pady=(2, 2))
            else:
                self.toggle_btn.pack_forget()
        self.entry.delete(0, "end")
        self.entry.focus()

    def toggle_mode(self):
        self.mode = "password" if self.mode == "otp" else "otp"
        self._render_mode()

    def try_unlock(self):
        val = self.entry.get()
        ok = self.app.db.unlock_with_totp(val) if self.mode == "otp" \
            else self.app.db.unlock_with_master(val)
        if ok:
            self.app.post_unlock()
        else:
            bad = "Incorrect or expired code." if self.mode == "otp" else "Incorrect Master Password."
            messagebox.showerror("Access Denied", bad)
            self.entry.delete(0, "end")


# ---------- Forgot password ----------

class ForgotPasswordFrame(ctk.CTkFrame):
    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app

        card = ctk.CTkFrame(self, fg_color=COL_CARD, corner_radius=2, width=410,
                             border_width=1, border_color=COL_BORDER)
        card.place(relx=0.5, rely=0.5, anchor="center")
        make_card_responsive(self, card, min_w=360, max_w=440, frac=0.46)

        ctk.CTkLabel(card, text="Reset Master Password", font=FONT_TITLE,
                     text_color=COL_TEXT).pack(pady=(18, 3), padx=28)
        ctk.CTkLabel(card, text="Enter the Recovery Key you saved at setup.\n"
                                 f"(A reset notice can also be sent to: "
                                 f"{app.db.get_recovery_email() or RECOVERY_EMAIL_DEFAULT})",
                     font=FONT_SMALL, text_color=COL_SUBTEXT, justify="center").pack(pady=(0, 12), padx=22)

        self.rk_entry = ctk.CTkEntry(card, placeholder_text="XXXX-XXXX-XXXX-XXXX-XXXX", width=300)
        self.rk_entry.pack(pady=6, padx=40)

        ctk.CTkButton(card, text="Verify Recovery Key", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, width=300,
                      command=self.verify).pack(pady=(10, 4))

        ctk.CTkButton(card, text="Email Me a Reset Notice", fg_color="transparent",
                      text_color=COL_SUBTEXT, hover_color=COL_PANEL, width=300,
                      command=self.send_email).pack(pady=4)

        ctk.CTkButton(card, text="← Back to Login", fg_color="transparent",
                      text_color=COL_ACCENT, hover_color=COL_PANEL, width=300,
                      command=self.app.show_login).pack(pady=(4, 18))

    def send_email(self):
        to_addr = self.app.db.get_recovery_email() or RECOVERY_EMAIL_DEFAULT
        ok, msg = send_recovery_notice(self.app.cfg, to_addr, masked_hint="Vault reset requested.")
        (messagebox.showinfo if ok else messagebox.showwarning)("Recovery Email", msg)

    def verify(self):
        rk = self.rk_entry.get().strip().upper()
        if self.app.db.unlock_with_recovery(rk):
            NewMasterPasswordDialog(self.app)
        else:
            messagebox.showerror("Invalid Key", "That recovery key doesn't match this vault.")


class NewMasterPasswordDialog(ctk.CTkToplevel):
    def __init__(self, app: CredentialsVaultApp):
        super().__init__(app)
        self.app = app
        self.title("Set New Master Password")
        self.geometry("400x270")
        self.configure(fg_color=COL_BG)
        self.grab_set()

        ctk.CTkLabel(self, text="Set a New Master Password", font=FONT_SUB,
                     text_color=COL_TEXT).pack(pady=(24, 14))
        self.pw1 = ctk.CTkEntry(self, placeholder_text="New Master Password", show="•", width=270)
        self.pw1.pack(pady=6)
        self.pw2 = ctk.CTkEntry(self, placeholder_text="Confirm", show="•", width=270)
        self.pw2.pack(pady=6)
        ctk.CTkLabel(self, text="A new Recovery Key will be generated.",
                     font=FONT_SMALL, text_color=COL_SUBTEXT, justify="center").pack(pady=10)
        ctk.CTkButton(self, text="Save New Password", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, width=270,
                      command=self.save).pack(pady=10)

    def save(self):
        p1, p2 = self.pw1.get(), self.pw2.get()
        if len(p1) < 8:
            messagebox.showerror("Weak Password", "Must be at least 8 characters.")
            return
        if p1 != p2:
            messagebox.showerror("Mismatch", "Passwords don't match.")
            return
        new_recovery_key = self.app.db.change_master_password(p1)
        self.destroy()
        RecoveryKeyDialog(self.app, new_recovery_key, on_close=self.app.post_unlock)


# ---------- Settings re-authentication gate ----------

class SettingsAuthFrame(ctk.CTkFrame):
    """Always shown before Settings, no matter what. Same OTP-first /
    Master-Password-fallback pattern as the login screen. Cancelling
    returns to the vault, not to Settings."""

    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app
        self.otp_available = app.db.is_totp_enabled() and HAS_TOTP
        self.mode = "otp" if self.otp_available else "password"

        self.card = ctk.CTkFrame(self, fg_color=COL_CARD, corner_radius=2, width=380,
                                  border_width=1, border_color=COL_BORDER)
        self.card.place(relx=0.5, rely=0.5, anchor="center")
        make_card_responsive(self, self.card, min_w=340, max_w=420, frac=0.42)

        ctk.CTkLabel(self.card, text="🔐 Confirm It's You", font=FONT_TITLE,
                     text_color=COL_TEXT).pack(pady=(20, 3), padx=28)
        self.sub_lbl = ctk.CTkLabel(self.card, font=FONT_SUB, text_color=COL_SUBTEXT,
                                     wraplength=280, justify="center")
        self.sub_lbl.pack(pady=(0, 20))

        self.entry = ctk.CTkEntry(self.card, width=270)
        self.entry.pack(pady=6, padx=40)
        self.entry.bind("<Return>", lambda e: self.confirm())

        self.confirm_btn = ctk.CTkButton(self.card, fg_color=COL_ACCENT,
                                          hover_color=COL_ACCENT_HOVER, width=270,
                                          command=self.confirm)
        self.confirm_btn.pack(pady=(14, 6))

        self.toggle_btn = ctk.CTkButton(self.card, fg_color="transparent",
                                         text_color=COL_ACCENT, hover_color=COL_PANEL,
                                         width=270, command=self.toggle_mode)
        self.toggle_btn.pack(pady=(2, 2))

        ctk.CTkButton(self.card, text="← Cancel", fg_color="transparent",
                      text_color=COL_SUBTEXT, hover_color=COL_PANEL, width=270,
                      command=self.app.show_main).pack(pady=(0, 20))

        self._render_mode()

    def _render_mode(self):
        if self.mode == "otp":
            self.sub_lbl.configure(text="Enter your Google Authenticator code to open Settings")
            self.entry.configure(placeholder_text="000000", show="", justify="center",
                                  font=("Consolas", 18))
            self.confirm_btn.configure(text="Verify")
            self.toggle_btn.configure(text="Can't access Authenticator? Use Master Password")
            self.toggle_btn.pack(pady=(2, 2))
        else:
            self.sub_lbl.configure(text="Re-enter your Master Password to open Settings")
            self.entry.configure(placeholder_text="Master Password", show="•", justify="left",
                                  font=("Segoe UI", 14))
            self.confirm_btn.configure(text="Confirm")
            if self.otp_available:
                self.toggle_btn.configure(text="Use Authenticator code instead")
                self.toggle_btn.pack(pady=(2, 2))
            else:
                self.toggle_btn.pack_forget()
        self.entry.delete(0, "end")
        self.entry.focus()

    def toggle_mode(self):
        self.mode = "password" if self.mode == "otp" else "otp"
        self._render_mode()

    def confirm(self):
        val = self.entry.get()
        if val == SETTINGS_DEFAULT_PASSWORD:
            self.app.show_settings()
            return
        ok = self.app.db.unlock_with_totp(val) if self.mode == "otp" \
            else self.app.db.unlock_with_master(val)
        if ok:
            self.app.show_settings()
        else:
            bad = "Incorrect or expired code." if self.mode == "otp" else "Incorrect Master Password."
            messagebox.showerror("Access Denied", bad)
            self.entry.delete(0, "end")


# ---------- Main vault ----------

class MainVaultFrame(ctk.CTkFrame):
    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app
        self.selected_category = "All"

        # ---- top nav bar ----
        # Compact, no-icon bar: [search, fixed width]  ---flex gap---
        # [grouped text-label action toolbar]. No divider lines; the action
        # buttons are grouped into a single bordered cluster instead of
        # floating loosely.
        TOPBAR_H = 56
        top = ctk.CTkFrame(self, fg_color=COL_CARD, height=TOPBAR_H, corner_radius=0,
                            border_width=0)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)
        sep = ctk.CTkFrame(self, fg_color=COL_BORDER, height=1, corner_radius=0)
        sep.pack(fill="x", side="top")

        # -- left: search, fixed sensible width instead of stretching edge to edge --
        search_zone = ctk.CTkFrame(top, fg_color="transparent")
        search_zone.pack(side="left", fill="y", padx=(16, 0))
        self.search_var = ctk.StringVar()
        search = ctk.CTkEntry(search_zone, textvariable=self.search_var, placeholder_text="Search vault...",
                               height=30, width=380, fg_color=COL_PANEL, border_width=1,
                               border_color=COL_BORDER)
        search.pack(expand=True)
        self.search_var.trace_add("write", lambda *_: self.refresh_list())

        # -- right: grouped action toolbar (single bordered cluster) --
        right = ctk.CTkFrame(top, fg_color=COL_PANEL, corner_radius=2,
                              border_width=1, border_color=COL_BORDER)
        right.pack(side="right", padx=16, pady=10)

        # Text-label action buttons (compact, no icons/emoji).
        menu_btns = [
            ("Add", dict(fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER),
             self.add_credential_dialog),
            ("Generate", dict(fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                        border_color=COL_BORDER, hover_color=COL_PANEL),
             self.open_generator),
            ("Settings", dict(fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                       border_color=COL_BORDER, hover_color=COL_PANEL),
             self.app.open_settings_gate),
            ("Lock", dict(fg_color=COL_DANGER, hover_color=COL_DANGER_HOVER),
             self.app.lock_vault),
        ]
        for label, style, command in menu_btns:
            ctk.CTkButton(right, text=label, font=FONT_SMALL, height=26, width=64,
                          command=command, **style).pack(side="left", padx=3, pady=3)

        # ---- body: sidebar + list ----
        body = ctk.CTkFrame(self, fg_color=COL_BG)
        body.pack(fill="both", expand=True)

        self.SIDEBAR_OPEN_W = 165
        self.SIDEBAR_COLLAPSED_W = 40
        self.sidebar_collapsed = False

        self.sidebar = ctk.CTkFrame(body, fg_color=COL_PANEL, width=self.SIDEBAR_OPEN_W, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        sb_head = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        sb_head.pack(fill="x", padx=8, pady=(10, 4))
        self.sb_toggle_btn = ctk.CTkButton(sb_head, text="☰", width=26, height=26, corner_radius=2,
                                            fg_color="transparent", text_color=COL_SUBTEXT,
                                            hover_color=COL_BORDER, command=self.toggle_sidebar)
        self.sb_toggle_btn.pack(side="left")
        self.sb_title = ctk.CTkLabel(sb_head, text="CATEGORIES", font=FONT_SMALL,
                                      text_color=COL_SUBTEXT)
        self.sb_title.pack(side="left", padx=(6, 0))

        self.cat_buttons_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.cat_buttons_frame.pack(fill="x", padx=4)

        self.list_container = ctk.CTkScrollableFrame(body, fg_color=COL_BG)
        self.list_container.pack(side="left", fill="both", expand=True, padx=16, pady=16)

        self.refresh_categories()
        self.refresh_list()

    def toggle_sidebar(self):
        self.sidebar_collapsed = not self.sidebar_collapsed
        if self.sidebar_collapsed:
            self.sidebar.configure(width=self.SIDEBAR_COLLAPSED_W)
            self.sb_title.pack_forget()
            self.cat_buttons_frame.pack_forget()
        else:
            self.sidebar.configure(width=self.SIDEBAR_OPEN_W)
            self.sb_title.pack(side="left", padx=(6, 0))
            self.cat_buttons_frame.pack(fill="x", padx=4)

    def refresh_categories(self):
        for w in self.cat_buttons_frame.winfo_children():
            w.destroy()
        cats = ["All", "General"] + [c for c in self.app.db.categories() if c != "General"]
        seen = set()
        for cat in cats:
            if cat in seen:
                continue
            seen.add(cat)
            is_active = cat == self.selected_category
            btn = ctk.CTkButton(
                self.cat_buttons_frame, text=cat, anchor="w",
                fg_color=COL_ACCENT if is_active else "transparent",
                text_color="white" if is_active else COL_SUBTEXT,
                hover_color=COL_BORDER, corner_radius=2,
                command=lambda c=cat: self.select_category(c)
            )
            btn.pack(fill="x", padx=4, pady=2)

    def select_category(self, cat):
        self.selected_category = cat
        self.refresh_categories()
        self.refresh_list()

    def refresh_list(self):
        for w in self.list_container.winfo_children():
            w.destroy()
        items = self.app.db.list_credentials(self.search_var.get(), self.selected_category)
        if not items:
            ctk.CTkLabel(self.list_container, text="No credentials found.",
                         text_color=COL_SUBTEXT, font=FONT_BODY).pack(pady=30)
            return
        for item in items:
            self._build_row(item)

    def _build_row(self, item):
        row = ctk.CTkFrame(self.list_container, fg_color=COL_CARD, corner_radius=2,
                            border_width=1, border_color=COL_BORDER)
        row.pack(fill="x", pady=6, padx=4)

        left = ctk.CTkFrame(row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=16, pady=12)
        ctk.CTkLabel(left, text=item["site"], font=("Segoe UI", 15, "bold"),
                     text_color=COL_TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(left, text=f"{item['username'] or '—'}   ·   {item['category']}",
                     font=FONT_SMALL, text_color=COL_SUBTEXT, anchor="w").pack(anchor="w")

        pw_var = ctk.StringVar(value="•" * 10)
        revealed = {"on": False}

        def toggle_reveal():
            revealed["on"] = not revealed["on"]
            pw_var.set(item["password"] if revealed["on"] else "•" * 10)

        ctk.CTkLabel(left, textvariable=pw_var, font=("Consolas", 13),
                     text_color=COL_SUBTEXT, anchor="w").pack(anchor="w", pady=(2, 0))

        right = ctk.CTkFrame(row, fg_color="transparent")
        right.pack(side="right", padx=12)
        ctk.CTkButton(right, text="👁", width=34, fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                      border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=toggle_reveal).pack(side="left", padx=3)
        ctk.CTkButton(right, text="Copy", width=54, fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                      border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=lambda: self.copy_password(item["password"])).pack(side="left", padx=3)
        ctk.CTkButton(right, text="Edit", width=54, fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                      border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=lambda: self.edit_credential_dialog(item)).pack(side="left", padx=3)
        ctk.CTkButton(right, text="Del", width=44, fg_color=COL_DANGER, hover_color=COL_DANGER_HOVER,
                      command=lambda: self.delete_credential(item)).pack(side="left", padx=3)

    def copy_password(self, password):
        if not HAS_CLIPBOARD:
            messagebox.showinfo("Clipboard", password)
            return
        pyperclip.copy(password)
        messagebox.showinfo("Copied", f"Password copied. Clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s.")

        def clear_later():
            time.sleep(CLIPBOARD_CLEAR_SECONDS)
            try:
                if pyperclip.paste() == password:
                    pyperclip.copy("")
            except Exception:
                pass
        threading.Thread(target=clear_later, daemon=True).start()

    def delete_credential(self, item):
        if messagebox.askyesno("Delete", f"Delete credential for '{item['site']}'?"):
            self.app.db.delete_credential(item["id"])
            self.refresh_categories()
            self.refresh_list()

    def add_credential_dialog(self):
        CredentialDialog(self.app, on_save=self._after_change)

    def edit_credential_dialog(self, item):
        CredentialDialog(self.app, item=item, on_save=self._after_change)

    def _after_change(self):
        self.refresh_categories()
        self.refresh_list()

    def open_generator(self):
        GeneratorDialog(self.app)


class CredentialDialog(ctk.CTkToplevel):
    def __init__(self, app: CredentialsVaultApp, item=None, on_save=None):
        super().__init__(app)
        self.app = app
        self.item = item
        self.on_save = on_save
        self.title("Edit Credential" if item else "Add Credential")
        self.geometry("440x520")
        self.minsize(380, 480)
        self.configure(fg_color=COL_BG)
        self.grab_set()

        # Inner Card Panel
        card = ctk.CTkFrame(self, fg_color=COL_CARD, corner_radius=2,
                             border_width=1, border_color=COL_BORDER)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        # Header Title
        title_text = "Edit Credential" if item else "Add Credential"
        ctk.CTkLabel(card, text=title_text, font=("Segoe UI", 16, "bold"), 
                     text_color=COL_TEXT).pack(anchor="w", padx=20, pady=(16, 4))

        # --- Form Body ---
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=20, pady=8)

        # Site / App
        ctk.CTkLabel(form, text="Site / App *", font=FONT_SMALL, text_color=COL_SUBTEXT).pack(anchor="w", pady=(4, 2))
        self.site = ctk.CTkEntry(form, placeholder_text="e.g., Google, GitHub")
        self.site.pack(fill="x", pady=(0, 8))

        # Username / Email
        ctk.CTkLabel(form, text="Username / Email", font=FONT_SMALL, text_color=COL_SUBTEXT).pack(anchor="w", pady=(4, 2))
        self.username = ctk.CTkEntry(form, placeholder_text="e.g., user@email.com")
        self.username.pack(fill="x", pady=(0, 8))

        # Password Row
        ctk.CTkLabel(form, text="Password *", font=FONT_SMALL, text_color=COL_SUBTEXT).pack(anchor="w", pady=(4, 2))
        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(fill="x", pady=(0, 8))
        
        self.password = ctk.CTkEntry(pw_row, show="•")
        self.password.pack(side="left", fill="x", expand=True, padx=(0, 6))

        # Password Actions (Visibility Toggle & Auto-Gen)
        self._show_pw = False
        self.toggle_btn = ctk.CTkButton(
            pw_row, text="👁", width=36, fg_color=COL_CARD, text_color=COL_TEXT,
            border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
            command=self._toggle_pw_visibility
        )
        self.toggle_btn.pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            pw_row, text="Gen", width=48, fg_color=COL_CARD, text_color=COL_TEXT,
            border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
            command=self.autogen
        ).pack(side="left")

        # Category
        ctk.CTkLabel(form, text="Category", font=FONT_SMALL, text_color=COL_SUBTEXT).pack(anchor="w", pady=(4, 2))
        self.category = ctk.CTkEntry(form, placeholder_text="General")
        self.category.pack(fill="x", pady=(0, 8))

        # Notes
        ctk.CTkLabel(form, text="Notes", font=FONT_SMALL, text_color=COL_SUBTEXT).pack(anchor="w", pady=(4, 2))
        self.notes = ctk.CTkTextbox(form, height=60, corner_radius=2, border_width=1, border_color=COL_BORDER)
        self.notes.pack(fill="both", expand=True, pady=(0, 4))

        # Populate Fields on Edit Mode
        if item:
            self.site.insert(0, item["site"])
            self.username.insert(0, item["username"] or "")
            self.password.insert(0, item["password"])
            self.category.insert(0, item["category"])
            self.notes.insert("1.0", item["notes"] or "")

        # --- Footer Action Buttons ---
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(10, 16))

        ctk.CTkButton(
            btn_row, text="Cancel", fg_color=COL_CARD, text_color=COL_TEXT,
            border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
            command=self.destroy
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            btn_row, text="Save Credential", fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
            command=self.save
        ).pack(side="right", fill="x", expand=True, padx=(4, 0))

    def _toggle_pw_visibility(self):
        self._show_pw = not self._show_pw
        self.password.configure(show="" if self._show_pw else "•")

    def autogen(self):
        pw = gen_password()
        self.password.delete(0, "end")
        self.password.insert(0, pw)

    def save(self):
        site = self.site.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        category = self.category.get().strip() or "General"
        notes = self.notes.get("1.0", "end").strip()

        if not site or not password:
            messagebox.showerror("Missing Fields", "Site and Password are required.")
            return

        if self.item:
            self.app.db.update_credential(self.item["id"], site, username, password, notes, category)
        else:
            self.app.db.add_credential(site, username, password, notes, category)

        self.destroy()
        if self.on_save:
            self.on_save()

class GeneratorDialog(ctk.CTkToplevel):
    def __init__(self, app: CredentialsVaultApp):
        super().__init__(app)
        self.title("Password Generator")
        self.geometry("400x420")
        self.minsize(360, 400)
        self.configure(fg_color=COL_BG)
        self.grab_set()

        # Card Container
        card = ctk.CTkFrame(self, fg_color=COL_CARD, corner_radius=2,
                             border_width=1, border_color=COL_BORDER)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        # Output Display
        self.result_var = ctk.StringVar(value=gen_password())
        self.result_lbl = ctk.CTkLabel(
            card, textvariable=self.result_var, font=("Consolas", 16, "bold"),
            text_color=COL_ACCENT, wraplength=320, justify="center"
        )
        self.result_lbl.pack(pady=(20, 10), padx=20, fill="x")

        # Keep wraplength synced on window resize
        self.bind("<Configure>", lambda e: self.result_lbl.configure(wraplength=max(200, card.winfo_width() - 40)))

        # Length Slider + Dynamic Label
        self.length_var = ctk.IntVar(value=16)
        self.length_lbl = ctk.CTkLabel(
            card, text=f"Length: {self.length_var.get()}", 
            font=FONT_SMALL, text_color=COL_SUBTEXT
        )
        self.length_lbl.pack(anchor="w", padx=24, pady=(6, 0))

        slider = ctk.CTkSlider(
            card, from_=8, to=48, number_of_steps=40, variable=self.length_var,
            command=self._on_slider_change
        )
        slider.pack(pady=(4, 12), padx=24, fill="x")

        # Character Set Options (2x2 Grid)
        opts_frame = ctk.CTkFrame(card, fg_color="transparent")
        opts_frame.pack(fill="x", padx=24, pady=4)

        self.upper = ctk.BooleanVar(value=True)
        self.lower = ctk.BooleanVar(value=True)
        self.digits = ctk.BooleanVar(value=True)
        self.symbols = ctk.BooleanVar(value=True)

        checkboxes = [
            ("Uppercase", self.upper, 0, 0),
            ("Lowercase", self.lower, 0, 1),
            ("Digits", self.digits, 1, 0),
            ("Symbols", self.symbols, 1, 1),
        ]

        for label, var, row, col in checkboxes:
            cb = ctk.CTkCheckBox(
                opts_frame, text=label, variable=var, font=FONT_SMALL,
                command=self.regen, corner_radius=2
            )
            cb.grid(row=row, column=col, sticky="w", padx=8, pady=4)
        
        opts_frame.grid_columnconfigure((0, 1), weight=1)

        # Action Buttons (Side-by-Side)
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(16, 20))

        ctk.CTkButton(
            btn_row, text="Regenerate", fg_color=COL_CARD, text_color=COL_TEXT, 
            border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
            command=self.regen
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            btn_row, text="Copy", fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
            command=self.copy_it
        ).pack(side="right", fill="x", expand=True, padx=(4, 0))

    def _on_slider_change(self, val):
        self.length_lbl.configure(text=f"Length: {int(val)}")
        self.regen()

    def regen(self, *_):
        pw = gen_password(
            int(self.length_var.get()), self.upper.get(), self.lower.get(),
            self.digits.get(), self.symbols.get()
        )
        self.result_var.set(pw)

    def copy_it(self):
        if HAS_CLIPBOARD:
            pyperclip.copy(self.result_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard.")


class TOTPSetupDialog(ctk.CTkToplevel):
    def __init__(self, app: CredentialsVaultApp, on_done=None):
        super().__init__(app)
        self.app = app
        self.on_done = on_done
        self.title("Set Up Google Authenticator")
        self.geometry("400x540")
        self.configure(fg_color=COL_BG)
        self.grab_set()

        if not HAS_TOTP:
            ctk.CTkLabel(self, text="Missing packages.\nRun:\npip install pyotp qrcode pillow",
                         font=FONT_BODY, text_color=COL_DANGER, justify="center").pack(pady=60)
            return

        # Fetch system PC Name and IP Address dynamically
        try:
            pc_name = socket.gethostname()
            pc_ip = socket.gethostbyname(pc_name)
            issuer = f"{pc_name} ({pc_ip})"
        except Exception:
            issuer = socket.gethostname()

        self.secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(self.secret).provisioning_uri(
            name="CVault", 
            issuer_name=issuer  # Displays "PC_NAME (192.168.x.x)" in Authenticator
        )

        ctk.CTkLabel(self, text="Scan with Google Authenticator", font=FONT_SUB,
                     text_color=COL_TEXT).pack(pady=(20, 10))

        qr_img = qrcode.make(uri).convert("RGB").resize((240, 240))
        ctk_img = ctk.CTkImage(light_image=qr_img, dark_image=qr_img, size=(240, 240))
        img_label = ctk.CTkLabel(self, image=ctk_img, text="")
        img_label.pack(pady=6)

        ctk.CTkLabel(self, text="Or enter this key manually:", font=FONT_SMALL,
                     text_color=COL_SUBTEXT).pack(pady=(10, 2))
        key_box = ctk.CTkFrame(self, fg_color=COL_PANEL, corner_radius=2,
                                border_width=1, border_color=COL_BORDER)
        key_box.pack(pady=4, padx=40, fill="x")
        ctk.CTkLabel(key_box, text=self.secret, font=("Consolas", 15, "bold"),
                     text_color=COL_ACCENT).pack(pady=10)

        ctk.CTkLabel(self, text="Then enter the 6-digit code it shows to confirm:",
                     font=FONT_SMALL, text_color=COL_SUBTEXT).pack(pady=(14, 4))
        self.code_entry = ctk.CTkEntry(self, placeholder_text="000000", width=150,
                                        justify="center", font=("Consolas", 17))
        self.code_entry.pack(pady=6)

        ctk.CTkButton(self, text="Confirm & Enable 2FA", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, width=260,
                      command=self.confirm).pack(pady=16)

    def confirm(self):
        code = self.code_entry.get().strip()
        totp = pyotp.TOTP(self.secret)
        if not totp.verify(code, valid_window=1):
            messagebox.showerror("Incorrect Code", "That code doesn't match. Try again.")
            return
        self.app.db.enable_totp(self.secret)
        messagebox.showinfo("Enabled", "Google Authenticator 2FA is now enabled.")
        self.destroy()
        if self.on_done:
            self.on_done()


# ---------- Settings (relaid out: left nav + right content panel) ----------

class SettingsFrame(ctk.CTkFrame):
    SECTIONS = ["Account & Recovery", "Two-Factor Auth", "Notifications", "Auto-Lock", "Backup"]

    def __init__(self, master, app: CredentialsVaultApp):
        super().__init__(master, fg_color=COL_BG)
        self.app = app
        self.active_section = self.SECTIONS[0]

        top = ctk.CTkFrame(self, fg_color=COL_CARD, height=58, corner_radius=0)
        top.pack(fill="x")
        ctk.CTkLabel(top, text="Settings", font=("Segoe UI", 17, "bold"),
                     text_color=COL_TEXT).pack(side="left", padx=20, pady=14)
        ctk.CTkButton(top, text="← Back to Vault", fg_color=COL_CARD, text_color=COL_TEXT, border_width=1,
                      border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=self.app.show_main).pack(side="right", padx=16, pady=10)
        sep = ctk.CTkFrame(self, fg_color=COL_BORDER, height=1, corner_radius=0)
        sep.pack(fill="x")

        body = ctk.CTkFrame(self, fg_color=COL_BG)
        body.pack(fill="both", expand=True)

        self.NAV_OPEN_W = 185
        self.NAV_COLLAPSED_W = 40
        self.nav_collapsed = False

        self.nav = ctk.CTkFrame(body, fg_color=COL_PANEL, width=self.NAV_OPEN_W, corner_radius=0)
        self.nav.pack(side="left", fill="y")
        self.nav.pack_propagate(False)

        nav_head = ctk.CTkFrame(self.nav, fg_color="transparent")
        nav_head.pack(fill="x", padx=8, pady=(10, 4))
        self.nav_toggle_btn = ctk.CTkButton(nav_head, text="☰", width=26, height=26, corner_radius=2,
                                             fg_color="transparent", text_color=COL_SUBTEXT,
                                             hover_color=COL_BORDER, command=self.toggle_nav)
        self.nav_toggle_btn.pack(side="left")
        self.nav_title = ctk.CTkLabel(nav_head, text="SECTIONS", font=FONT_SMALL, text_color=COL_SUBTEXT)
        self.nav_title.pack(side="left", padx=(6, 0))

        self.nav_buttons_frame = ctk.CTkFrame(self.nav, fg_color="transparent")
        self.nav_buttons_frame.pack(fill="x", padx=4)
        self.nav_buttons = {}
        for section in self.SECTIONS:
            btn = ctk.CTkButton(self.nav_buttons_frame, text=section, anchor="w", corner_radius=2,
                                 fg_color=(COL_ACCENT if section == self.active_section else "transparent"),
                                 text_color=("white" if section == self.active_section else COL_SUBTEXT),
                                 hover_color=COL_BORDER,
                                 command=lambda s=section: self.select_section(s))
            btn.pack(fill="x", padx=4, pady=2)
            self.nav_buttons[section] = btn

        self.content = ctk.CTkScrollableFrame(body, fg_color=COL_BG)
        self.content.pack(side="left", fill="both", expand=True, padx=20, pady=16)

        self.render_section()

    def toggle_nav(self):
        self.nav_collapsed = not self.nav_collapsed
        if self.nav_collapsed:
            self.nav.configure(width=self.NAV_COLLAPSED_W)
            self.nav_title.pack_forget()
            self.nav_buttons_frame.pack_forget()
        else:
            self.nav.configure(width=self.NAV_OPEN_W)
            self.nav_title.pack(side="left", padx=(6, 0))
            self.nav_buttons_frame.pack(fill="x", padx=4)

    def select_section(self, section):
        self.active_section = section
        for s, btn in self.nav_buttons.items():
            is_active = s == section
            btn.configure(fg_color=(COL_ACCENT if is_active else "transparent"),
                          text_color=("white" if is_active else COL_SUBTEXT))
        self.render_section()

    def render_section(self):
        for w in self.content.winfo_children():
            w.destroy()
        if self.active_section == "Account & Recovery":
            self._render_account()
        elif self.active_section == "Two-Factor Auth":
            self._render_totp()
        elif self.active_section == "Notifications":
            self._render_smtp()
        elif self.active_section == "Auto-Lock":
            self._render_autolock()
        elif self.active_section == "Backup":
            self._render_backup()

    def _card(self, title):
        frame = ctk.CTkFrame(self.content, fg_color=COL_CARD, corner_radius=2,
                              border_width=1, border_color=COL_BORDER)
        frame.pack(fill="x", pady=10)
        ctk.CTkLabel(frame, text=title, font=("Segoe UI", 16, "bold"),
                     text_color=COL_TEXT).pack(anchor="w", padx=18, pady=(14, 6))
        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(padx=18, pady=(0, 16), anchor="w")
        return inner

    # ---- Account & Recovery ----
    def _render_account(self):
        sec1 = self._card("Change Master Password")
        self.new_pw = ctk.CTkEntry(sec1, placeholder_text="New Master Password", show="•", width=270)
        self.new_pw.pack(pady=4)
        ctk.CTkButton(sec1, text="Update Master Password", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, command=self.update_master).pack(pady=8)

        sec2 = self._card("Recovery Email")
        self.rec_email = ctk.CTkEntry(sec2, width=270)
        self.rec_email.insert(0, self.app.db.get_recovery_email() or "")
        self.rec_email.pack(pady=4)
        ctk.CTkButton(sec2, text="Save Recovery Email", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, command=self.update_email).pack(pady=8)

    def update_master(self):
        new_pw = self.new_pw.get()
        if len(new_pw) < 8:
            messagebox.showerror("Weak Password", "Must be at least 8 characters.")
            return
        new_recovery_key = self.app.db.change_master_password(new_pw)
        RecoveryKeyDialog(self.app, new_recovery_key, on_close=lambda: None)
        self.new_pw.delete(0, "end")

    def update_email(self):
        email = self.rec_email.get().strip()
        self.app.db.set_recovery_email(email)
        self.app.cfg["recovery_notify_email"] = email
        save_config(self.app.cfg)
        messagebox.showinfo("Saved", "Recovery email updated.")

    # ---- Two-Factor Auth ----
    def _render_totp(self):
        sec = self._card("Two-Factor Authentication (Google Authenticator)")
        enabled = self.app.db.is_totp_enabled()
        self.totp_status = ctk.CTkLabel(
            sec, text=f"Status: {'Enabled ✅' if enabled else 'Disabled'}",
            font=FONT_BODY, text_color=COL_SUCCESS if enabled else COL_SUBTEXT)
        self.totp_status.pack(anchor="w", pady=(0, 8))
        self.totp_btn = ctk.CTkButton(
            sec, text=("Disable 2FA" if enabled else "Enable 2FA"),
            fg_color=(COL_DANGER if enabled else COL_ACCENT),
            hover_color=(COL_DANGER_HOVER if enabled else COL_ACCENT_HOVER),
            command=self.toggle_totp)
        self.totp_btn.pack(pady=4)
        ctk.CTkLabel(sec, text="Once enabled, your Authenticator code becomes the\n"
                               "default way to unlock the vault and open Settings.\n"
                               "Master Password stays available as a fallback if you\n"
                               "ever can't reach your Authenticator.",
                     font=FONT_SMALL, text_color=COL_SUBTEXT, justify="left").pack(anchor="w", pady=(6, 0))

    def toggle_totp(self):
        if self.app.db.is_totp_enabled():
            if messagebox.askyesno("Disable 2FA", "Turn off Google Authenticator 2FA?"):
                self.app.db.disable_totp()
                self.totp_status.configure(text="Status: Disabled", text_color=COL_SUBTEXT)
                self.totp_btn.configure(text="Enable 2FA", fg_color=COL_ACCENT,
                                         hover_color=COL_ACCENT_HOVER, command=self.toggle_totp)
        else:
            if not HAS_TOTP:
                messagebox.showerror("Missing Packages",
                                      "Run: pip install pyotp qrcode pillow")
                return
            TOTPSetupDialog(self.app, on_done=self.refresh_totp_status)

    def refresh_totp_status(self):
        enabled = self.app.db.is_totp_enabled()
        self.totp_status.configure(text=f"Status: {'Enabled ✅' if enabled else 'Disabled'}",
                                    text_color=COL_SUCCESS if enabled else COL_SUBTEXT)
        self.totp_btn.configure(text=("Disable 2FA" if enabled else "Enable 2FA"),
                                 fg_color=(COL_DANGER if enabled else COL_ACCENT),
                                 hover_color=(COL_DANGER_HOVER if enabled else COL_ACCENT_HOVER))

    # ---- Notifications (SMTP) ----
    def _render_smtp(self):
        sec = self._card("SMTP (for optional reset notice emails)")
        self.smtp_enabled = ctk.BooleanVar(value=self.app.cfg.get("smtp_enabled", False))
        ctk.CTkCheckBox(sec, text="Enable SMTP sending", variable=self.smtp_enabled).pack(anchor="w", pady=4)
        self.smtp_email = ctk.CTkEntry(sec, placeholder_text="Your sender Gmail address", width=270)
        self.smtp_email.insert(0, self.app.cfg.get("smtp_email", ""))
        self.smtp_email.pack(pady=4)
        self.smtp_pw = ctk.CTkEntry(sec, placeholder_text="Gmail App Password (not your login pw)",
                                     show="•", width=270)
        self.smtp_pw.insert(0, self.app.cfg.get("smtp_app_password", ""))
        self.smtp_pw.pack(pady=4)
        ctk.CTkButton(sec, text="Save SMTP Settings", fg_color=COL_ACCENT,
                      hover_color=COL_ACCENT_HOVER, command=self.update_smtp).pack(pady=8)

    def update_smtp(self):
        self.app.cfg["smtp_enabled"] = self.smtp_enabled.get()
        self.app.cfg["smtp_email"] = self.smtp_email.get().strip()
        self.app.cfg["smtp_app_password"] = self.smtp_pw.get()
        save_config(self.app.cfg)
        messagebox.showinfo("Saved", "SMTP settings updated.")

    # ---- Auto-Lock ----
    def _render_autolock(self):
        sec = self._card("Auto-Lock Timer (minutes)")
        self.lock_min = ctk.CTkEntry(sec, width=88)
        self.lock_min.insert(0, str(self.app.cfg.get("auto_lock_minutes", AUTO_LOCK_MINUTES)))
        self.lock_min.pack(pady=4)
        ctk.CTkButton(sec, text="Save", fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
                      command=self.update_lock).pack(pady=8)

    def update_lock(self):
        try:
            minutes = int(self.lock_min.get())
        except ValueError:
            messagebox.showerror("Invalid", "Enter a number.")
            return
        self.app.cfg["auto_lock_minutes"] = minutes
        save_config(self.app.cfg)
        messagebox.showinfo("Saved", "Auto-lock timer updated.")

    # ---- Backup ----
    def _render_backup(self):
        sec = self._card("Backup")
        ctk.CTkButton(sec, text="Export Encrypted Backup (.cvault)", fg_color=COL_CARD, text_color=COL_TEXT,
                      border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=self.export_backup).pack(pady=4)
        ctk.CTkButton(sec, text="Import Backup (.cvault)", fg_color=COL_CARD, text_color=COL_TEXT,
                      border_width=1, border_color=COL_BORDER, hover_color=COL_PANEL,
                      command=self.import_backup).pack(pady=4)

    def export_backup(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".cvault",
                                             filetypes=[("Credentials Vault Backup", "*.cvault")])
        if path:
            self.app.db.export_backup(path)
            messagebox.showinfo("Exported", f"Backup saved to {path}")

    def import_backup(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(filetypes=[("Credentials Vault Backup", "*.cvault")])
        if path and messagebox.askyesno("Import", "This will replace the current vault. Continue?"):
            self.app.db.import_backup(path)
            messagebox.showinfo("Imported", "Backup restored. Please restart the app.")
            self.app.db.key = None
            self.app.show_login()


# ============================================================================
# MAIN
# ============================================================================

def main():
    app = CredentialsVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
