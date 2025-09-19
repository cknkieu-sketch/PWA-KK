# PassVault (PWA)

A simple mobile-friendly, **offline** password vault. Your data is encrypted on-device with AES‑GCM. Unlock with **biometrics (WebAuthn)** when available, with **PIN** fallback. Includes a password generator and **encrypted import/export** so you can move to a new device securely.

## Features
- PWA: install to home screen, works offline
- AES‑GCM 256-bit encryption with key wrapped by PIN (PBKDF2)
- Optional biometric gating via WebAuthn (platform authenticator) + PIN
- Password generator with length and character-set controls
- Encrypted backup (.vault) export and import

## Quick start
1. Serve these files (e.g., GitHub Pages) or open `index.html` directly.
2. On first launch, choose a **PIN** and optionally enable **biometrics**.
3. Add entries. Use **Export Encrypted Backup** to create a portable backup file.
4. To restore, use **Import Backup** and enter your backup password.

> **Biometrics:** Some browsers/devices require HTTPS and platform authenticator support. If enabled, unlock requires a WebAuthn assertion **and** your PIN.

## Security model
- Vault content is encrypted with an AES‑GCM master key.
- Master key is wrapped by a PBKDF2‑SHA256 key derived from your PIN (150k iterations).
- Backups are encrypted with a backup password (PBKDF2 200k).
- Import disables biometrics (credential is device‑bound). You can reset the vault to recreate biometrics on the new device.

## Deploy to GitHub Pages
- Push these files to a repo, enable **Pages** from the root.
- Open the URL on your phone and **Add to Home screen**.

© 2025-09-19
