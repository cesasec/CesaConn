# CesaConn

<div align="center">
  <img src="./image2.webp" alt="CesaConn Logo" width="200"/>
  
  ### Ready. Set. Connect.
  
  *CesaConn — connecting all your devices together securely.*

  ![Status](https://img.shields.io/badge/status-in%20development-yellow)
  ![License](https://img.shields.io/badge/license-LGPL%203.0-blue)
  ![Language](https://img.shields.io/badge/language-Rust-orange)
  ![Coming](https://img.shields.io/badge/coming-2026%2F2027-gold)
</div>

---

## What is CesaConn?

CesaConn is a **secure, serverless, cross-platform device synchronization application** built by CesaSec.

Sync your files, clipboard, notifications, and more — across all your devices — without any central server ever seeing your data. Your data stays yours. Always.

---

## Why CesaConn?

Most sync solutions force you to trust a third party with your data. CesaConn is different:

- **No central server** — data travels directly between your devices
- **End-to-end encrypted** — nobody can read your data, not even us
- **Two independent keys** — one for authentication, one for data
- **You are in full control** — every feature can be turned on or off
- **Zero data collection** — we don't know who you are, and we don't want to
- **Every feature is off by default after updates** — you decide what to enable

---

## Security Architecture

CesaConn is built with a military-grade security stack:

| Layer | Technology | Purpose |
|---|---|---|
| Key Exchange | X25519 ECDH | Secure shared secret — never transmitted |
| Auth Encryption | AES-256-GCM | Encrypt authentication hash |
| Data Encryption | AES-256-GCM | Encrypt transmitted data |
| Key Derivation | Argon2 | Password → cryptographic key |
| Salt Generation | OS Entropy (SysRng) | Cryptographically secure randomness |
| Packet Signing | Ed25519 | Every packet signed — signatures removed after verification |
| Memory Safety | Zeroize | Keys and secrets wiped from RAM after use |

---

### Two Independent Keys

CesaConn uses **two completely separate passwords and keys**:

```
Password 1 (auth)   → Argon2 → Auth Key    → used ONLY for authentication
Password 2 (data)   → Argon2 → Data Key    → used ONLY for data transfer
```

If one key is compromised — the other remains secure. Both must be broken simultaneously for an attacker to succeed.

---

### Full Connection Flow

```
════════════════════════════════════════
  PHASE 1 — ECDH KEY EXCHANGE
════════════════════════════════════════

Device A                              Device B
   │                                     │
   │──── ECDH Public Key ──────────────►│
   │◄─── ECDH Public Key ───────────────│
   │                                     │
   │  Both independently derive          │
   │  the same shared_secret             │
   │  shared_secret is NEVER transmitted │


════════════════════════════════════════
  PHASE 2 — MUTUAL AUTHENTICATION
════════════════════════════════════════

Device A                              Device B
   │                                     │
   │  hash_auth = hash(auth_password)    │
   │  encrypted = AES256(hash_auth,      │
   │              shared_secret)         │
   │  signature = Ed25519(encrypted)     │
   │                                     │
   │──── [encrypted + signature] ──────►│
   │◄─── [encrypted + signature] ────────│
   │                                     │
   │  verify Ed25519 signature           │
   │  decrypt AES256                     │
   │  compare hash_auth                  │
   │                                     │
   │  match  → ✅ authenticated          │
   │  no match → ❌ connection rejected  │


════════════════════════════════════════
  PHASE 3 — ENCRYPTED DATA TRANSFER
════════════════════════════════════════

Device A                              Device B
   │                                     │
   │  encrypted = AES256(data,           │
   │              data_key)              │
   │  signature = Ed25519(encrypted)     │
   │                                     │
   │◄════ [encrypted + signature] ══════►│
   │                                     │
   │  verify Ed25519 signature           │
   │  decrypt AES256                     │
   │  signature removed after verify     │
   │  → clean data ✅                   │
```

---

### Why this matters

| Attack | CesaConn |
|---|---|
| Man-in-the-middle | ❌ Blocked by mutual authentication |
| Packet tampering | ❌ Blocked by Ed25519 signatures |
| Replay attack | ❌ Blocked by unique nonces |
| Eavesdropping | ❌ Blocked by AES-256-GCM |
| Auth key compromise | ❌ Data key still secure |
| Data key compromise | ❌ Auth key still secure |
| Brute force password | ❌ Blocked by Argon2 KDF |
| Key theft from RAM | ❌ Keys wiped by Zeroize |
| Server breach | ❌ There is no server |

---

## Features

### Planned for v1.0
- [ ] File synchronization
- [ ] Clipboard sync
- [ ] Notification mirroring
- [ ] End-to-end encryption
- [ ] Mutual authentication with dual-key system
- [ ] Zero Trust device authorization
- [ ] Full offline / serverless operation

### Transport Support
- [ ] WiFi / LAN (TCP + UDP)
- [ ] WiFi Hotspot
- [ ] Bluetooth LE

### Platform Support
- [ ] Windows
- [ ] Linux
- [ ] Android
- [ ] macOS *(planned)*
- [ ] iOS *(under consideration)*

---

## Philosophy

> Every feature is **off by default** after updates. You decide what to enable. We don't decide for you.

CesaConn is built on the belief that software should serve the user — not the developer. No forced features. No hidden telemetry. No dark patterns.

---

## Repository Structure

```
CesaConnCore/
├── cesa_conn_crypto/        # Cryptography module
│   ├── src/
│   │   ├── aes.rs           # AES-256-GCM encryption/decryption
│   │   ├── salt.rs          # Secure salt generation
│   │   ├── pswd_manager.rs  # Argon2 key derivation
│   │   └── lib.rs
│   └── Cargo.toml
│
└── cesa_conn_networker/     # Networking module
    ├── src/
    │   ├── udp_networker.rs  # Device discovery (UDP broadcast)
    │   ├── tcp_networker.rs  # Data transfer (TCP)
    │   └── lib.rs
    └── Cargo.toml
```

---

## Building from Source

### Requirements
- Rust 1.75+
- Cargo

### Build

```bash
git clone https://github.com/czarekkdev/CesaConnCore
cd CesaConnCore
cargo build --release
```

### Run Tests

```bash
# Test cryptography module
cargo test -p cesa_conn_crypto

# Test networking module
cargo test -p cesa_conn_networker
```

---

## Privacy

CesaConn is designed with privacy as a core principle, not an afterthought:

- **No account required** to use the application
- **No telemetry** — we don't collect usage data
- **No analytics** — we don't track you
- **No servers** — there is nothing to breach
- **Open source core** — verify our claims yourself

---

## License

CesaConnCore is licensed under [LGPL 3.0](LICENSE).

This means you can use this library in your own projects, including proprietary ones, as long as any modifications to CesaConnCore itself are kept open source.

CesaConn application — Proprietary (CesaSec)

---

## About CesaSec

**CesaSec** — *Where Innovation Meets Security.*

CesaConn is a product of CesaSec, an independent security-focused software company.

---

<div align="center">
  <i>Built with ❤️ and Rust 🦀</i>
</div>
