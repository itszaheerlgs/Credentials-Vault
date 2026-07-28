# Dether Vault

A local, encrypted credentials/password manager built with CustomTkinter.

## 1. Install dependencies

```bash
pip install -r requirements.txt
```

## 2. Run it

```bash
python dether_vault.py
```

First run walks you through:
1. Setting a **Master Password** (min 8 chars)
2. Setting a **Quick-Unlock PIN** (default suggestion: `1234` — change it)
3. Optional **Recovery Email**
4. Shows you a **Recovery Key** ONE TIME — save it somewhere safe (screenshot,
   write it down, put it in another password manager). This is the only way
   to reset your master password later. There is no other backdoor.

## 3. Build a single .exe with PyInstaller

Make sure `cv.png` and `cv.ico` are in the **same folder** as `dether_vault.py`
(both are included in this download) before building:

```bash
pyinstaller --onefile --noconsole --name "DetherVault" --icon=cv.ico ^
  --add-data "cv.png;." --add-data "cv.ico;." dether_vault.py
```

The exe will appear in `dist/DetherVault.exe`, with the CV shield as both the
taskbar/title-bar icon and the .exe file icon itself. Vault data is stored in
`%USERPROFILE%\DetherVault\vault.db` and `config.json` (not next to the exe),
so it survives you moving/rebuilding the exe.

> If CustomTkinter assets don't get bundled correctly, add this before building:
> ```bash
> pyinstaller --onefile --noconsole --name "DetherVault" ^
>   --collect-all customtkinter dether_vault.py
> ```

## 4. Optional: enable email reset notices

By default no email is ever sent. If you want the "Forgot Password" screen's
**Email Me a Reset Notice** button to actually work:

1. Go to **Settings → SMTP**
2. Check "Enable SMTP sending"
3. Enter a Gmail address you control as the sender
4. Generate a **Gmail App Password** (Google Account → Security → 2-Step
   Verification → App Passwords) and paste that — never your real Gmail
   login password — into the "Gmail App Password" field
5. Set your **Recovery Email** to whatever inbox you want the notice sent to

This email only ever contains a masked reminder + "use your Recovery Key" —
your real master password or vault contents are never emailed, because they
are never stored anywhere in a recoverable form.

## 5. Two-Factor Authentication (Google Authenticator)

Optional, off by default. To turn it on:

1. Unlock the vault, go to **Settings → Two-Factor Authentication**
2. Click **Enable 2FA**
3. Scan the QR code with Google Authenticator (or Authy/Microsoft Authenticator,
   any standard TOTP app), or type in the manual key shown below it
4. Enter the 6-digit code it generates to confirm

From then on, after entering your Master Password or PIN, you'll be asked for
a 6-digit code before the vault opens. The secret is stored encrypted inside
the vault itself (never in plaintext), and it's automatically re-encrypted
if you ever change your master password.

If you lose access to your authenticator app, use **Forgot Password → Recovery
Key** to reset your master password — this generates a fresh vault key, and
you'll need to re-enable 2FA afterward (scan a new QR code) since 2FA can't be
bypassed any other way by design.

**Settings is also gated behind 2FA once it's enabled** — opening Settings
from the main vault requires a fresh 6-digit code, not just your master
password/PIN. Before 2FA is enabled, Settings stays reachable directly (so
there's a way to turn 2FA on in the first place).

> Note: if `pyotp` / `qrcode` / `Pillow` aren't installed, the app still runs
> fine — the 2FA option in Settings will just tell you which packages to
> install.

## Security model (short version)

- Every stored password is encrypted with **Fernet (AES-128-CBC + HMAC-SHA256)**
- The encryption key is derived from your Master Password via
  **PBKDF2-HMAC-SHA256, 390,000 iterations**
- The PIN unlocks a *wrapped copy* of the same key (so PIN convenience
  doesn't weaken the master password's security)
- The Recovery Key unlocks another wrapped copy of the key, for password resets
- Nothing is ever stored in plaintext: not the master password, not the PIN,
  not the recovery key — only salted verifier hashes and encrypted key wraps
