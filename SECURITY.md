
## `SECURITY.md`

```md
# SECURITY.md — CryptoVault

This document describes the threat model and security controls implemented in CryptoVault.

## Security Goals
- Protect stored passwords against offline cracking (Argon2id).
- Reduce online guessing and credential stuffing (rate limiting + uniform errors).
- Provide confidentiality and integrity of messages (E2EE via ECDH + AES-GCM).
- Provide sender authenticity for messages (ECDSA signatures).
- Provide tamper-evident audit logs (Merkle Tree) and make rewrites costly (Proof-of-Work).

## Threat Model & Mitigations

### 1) Brute-force / Credential Stuffing
**Threat:** Repeated login attempts or reused leaked passwords.  
**Mitigations:**
- Argon2id for password hashing (memory-hard).
- Rate limiting / cooldown after repeated failures.
- Strong password policy (length + digit + uppercase + symbol).
- Uniform error responses to reduce user enumeration.

### 2) MITM (Man-in-the-Middle) During Key Exchange
**Threat:** Attacker substitutes public keys or intercepts messages.  
**Mitigations:**
- ECDH derives shared secret; AES-GCM provides confidentiality + integrity.
- ECDSA signatures provide message authenticity.
- Public key verification is required in real deployments:
  - fingerprint verification
  - PKI or certificate pinning
  - key transparency approaches

> Note: Without authenticated public keys, a MITM could replace keys and decrypt messages. For a university project, clearly document how keys are exchanged/verified.

### 3) Log Tampering (Audit Ledger)
**Threat:** Attacker modifies or deletes audit events to hide actions.  
**Mitigations:**
- Merkle root per block binds events.
- Block hash includes previous block hash (hash chain).
- Proof-of-Work adds computational cost to rewriting history.
- Store ledger with restrictive filesystem permissions.
- Optional: export ledger to external storage for redundancy.

### 4) Replay Attacks
**Threat:** Replay of old ciphertexts or repeated audit events.  
**Mitigations:**
- Unique nonce for every AES-GCM encryption.
- Include timestamps and monotonic IDs in audit events.
- Signature binds ciphertext to sender identity.

### 5) Secret / Key Exposure
**Threat:** Private keys, TOTP secrets, or session tokens leak.  
**Mitigations:**
- Do not hardcode secrets in source code.
- Avoid printing secrets in logs.
- Use file permissions and environment variables where possible.
- Rotate secrets / invalidate sessions after suspected compromise.

## Security Limitations (Educational Project)
- No formal audit or penetration testing.
- Simplified identity and key management compared to production messengers.
- Custom crypto exists only for education; modern primitives from `cryptography` should be used for real security.

## Reporting
If a vulnerability is found: document steps to reproduce and add tests before fixing.





/