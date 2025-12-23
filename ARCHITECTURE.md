# USER_GUIDE.md — CryptoVault

This guide explains how to use CryptoVault as an end user.

## 1) Registration (Password + 2FA)
1. Start the app (CLI or Flask UI).
2. Choose **Register**.
3. Enter username and a strong password.
4. The app returns a TOTP provisioning URI (QR code).
5. Scan it with an authenticator app (Google Authenticator / Authy).
6. Confirm by entering the current 6-digit code.

## 2) Login
1. Choose **Login**.
2. Enter username + password.
3. Enter current TOTP code.
4. On success you receive a session token (or an authenticated session).

If rate limiting triggers, wait for the cooldown window.

## 3) Secure Messaging (E2EE)
1. Exchange public keys with your peer (preferably out-of-band).
2. Sender encrypts message and signs it.
3. Receiver verifies signature and decrypts.

If signature verification fails: treat the message as tampered and discard it.

## 4) File Encryption
1. Choose **Encrypt File**.
2. Select the file path.
3. Enter passphrase.
4. CryptoVault derives a key using PBKDF2 and encrypts using AES-256 (AES-GCM recommended).
5. Output is an encrypted package (salt + nonce + ciphertext).

To decrypt, use the same passphrase.

## 5) Audit Ledger Verification (Optional)
- Verify block hashes link correctly.
- Recompute Merkle roots to confirm event integrity.
- Verify proof-of-work is valid at the chosen difficulty.
    




