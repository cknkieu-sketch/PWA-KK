# Vaultie — Secure Offline Vault (PWA)

A lightweight, **installable mobile web app** to store and manage usernames, passwords, and app/site URLs. Everything is **encrypted on-device** and never leaves your phone unless you export a backup. Supports optional **biometric unlock (passkey)** where supported.

## Features
- **On-device encryption:** AES‑256‑GCM; vault key wrapped by your **Master Password** (PBKDF2/SHA‑256, 250k iterations)
- **Biometric unlock:** Uses WebAuthn **PRF extension** to derive a device-bound secret and unwrap the vault key (Android/Chrome, iOS 17+/macOS Safari 17+, modern Chromium). If PRF isn’t available, the app falls back gracefully to Master Password unlock.
- **Password generator:** Choose length (8–64) and include/exclude lowercase, uppercase, numbers, symbols.
- **Import/Export:** Export an **encrypted** backup JSON. Import it on a new device and unlock with the same Master Password (and re‑enable biometrics on that device if desired).
- **PWA:** Works offline; can be installed to Home Screen.

## Security Notes
- Your data is stored in IndexedDB as **encrypted ciphertext**.
- The vault’s Data Encryption Key (DEK) is randomly generated and **wrapped** 2 ways:
  1) with a key derived from your Master Password (mandatory), and
  2) **optionally** with a device-bound secret via WebAuthn PRF (for biometric-only unlock).
- The backup export is **already encrypted**. Keep it safe. If you forget the Master Password and biometric isn’t configured, **data cannot be recovered**.

## Setup (GitHub Pages)
1. Create a new GitHub repo, e.g. `vaultie`.
2. Upload the files in this ZIP to the repo root.
3. In GitHub, go to **Settings → Pages → Branch: main → /(root)**. Enable Pages.
4. Visit your site at `https://<your-username>.github.io/<repo>/` (HTTPS required for biometrics).
5. On first load, create a **Master Password**. Optionally **Enable Biometric Unlock**.
6. **Install** to your Home Screen for a native feel.

## Usage
- **Add / Edit / Delete** entries (name, URL, username, password).
- Use the **Generator** to create strong passwords respecting your chosen policy.
- **Export backup** → stores encrypted JSON to your device.
- **Import backup** → select a previously exported JSON to restore the vault.
- **Lock** anytime; the app also requires unlock after reload.

## Compatibility
- Works best on modern Chromium and Safari (iOS 17+). Biometric‑only unlock requires WebAuthn **PRF** support; otherwise you can still use Master Password unlock, and you may use biometric as a confirmation gate only.

## Development
No build step. Pure HTML/CSS/JS + Web Crypto + WebAuthn.

