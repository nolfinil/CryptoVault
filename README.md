# CryptoVault — Secure Messaging & Encrypted File Storage (Python + Flask)

CryptoVault is an educational security suite demonstrating modern cryptography and secure engineering practices.  
It provides secure authentication (Argon2id + TOTP), end-to-end encrypted messaging (ECDH + AES-GCM + ECDSA), encrypted file storage (AES-256 + PBKDF2), and a tamper-evident audit ledger (Merkle Tree + Proof-of-Work).

> Educational scope: the project is designed for university defense and learning. It is not security-audited for production use.

## Features

### Auth
- Password hashing: **Argon2id** (argon2-cffi)
- Multi-factor authentication: **TOTP (2FA)** (pyotp)
- Basic brute-force protection: rate limiting / cooldown

### Messaging (E2EE)
- Key agreement: **ECDH (P-256)**
- Key derivation: **HKDF-SHA256**
- Encryption: **AES-GCM**
- Sender authenticity: **ECDSA signatures**

### File Storage
- File encryption: **AES-256 (AES-GCM recommended)**
- Passphrase KDF: **PBKDF2-HMAC-SHA256**
- Stores salt + nonce + ciphertext (and tag)

### Blockchain / Audit Ledger
- Event integrity: **Merkle Tree**
- Tamper resistance: **Proof-of-Work**
- Chain of blocks with previous hash

### Custom Crypto (Educational)
- Merkle Tree implementation from scratch
- Modular exponentiation (RSA math helper)
- Vigenère cipher (classic cipher demo)

## Requirements
- Python **3.10+**

## Installation

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt

   

