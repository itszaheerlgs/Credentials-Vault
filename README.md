# 🔒 Credentials Vault

**Credentials Vault** is a lightweight, secure, and modern desktop password manager built with Python and `customtkinter`. It features strong zero-knowledge AES encryption, two-factor authentication via Google Authenticator, a modern light-themed responsive GUI, and offline-first storage.

---

## ✨ Features

- **🔐 Robust Zero-Knowledge Encryption**:
  - Encrypted at rest using **Fernet (AES-128-CBC + HMAC)**.
  - Keys derived via **PBKDF2-HMAC-SHA256** with 390,000 iterations.
  - No plain-text passwords or master keys are ever stored on disk or sent over a network.
- **📱 2FA with Google Authenticator**:
  - Live 6-digit TOTP unlock as the primary option when enabled.
  - Instant Master Password fallback if your mobile device is unavailable.
- **🛡️ Account Recovery Flow**:
  - Generates a unique 20-character **Recovery Key** during setup.
  - Safely reset a forgotten master password without losing existing vault data.
  - *Optional*: Send reset notification emails via custom SMTP settings.
- **🎨 Modern & Responsive UI**:
  - Clean light theme styled with custom flat-bordered UI components.
  - Auto-resizing card components for different screen resolutions.
  - Collapsible sidebar for categories and settings navigation.
- **💼 Vault Management & Tools**:
  - Full CRUD functionality (Add, Edit, Delete, View credentials).
  - Built-in customizable strong password generator (8–48 characters).
  - Clipboard copy with auto-clearing after 20 seconds.
  - Adjustable Inactivity Auto-Lock timer.
  - Native `.cvault` file backup export and import.

---

## 🛠️ Requirements & Installation

### Option 1: Run from Python Source

#### Prerequisites
- **Python 3.9+** installed on your system.

#### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/credentials-vault.git](https://github.com/your-username/credentials-vault.git)
cd credentials-vault
