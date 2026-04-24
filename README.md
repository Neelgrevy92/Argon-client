# Argon Messenger

Argon is a secure, terminal-based (TUI) peer-to-peer chat client designed for high-risk environments. It routes all traffic through the **I2P network** via the SAM protocol (`i2pd`) and enforces strict **End-to-End PGP Encryption**.

Argon is built with Operational Security (OpSec) as its core philosophy: it features encrypted key storage at rest, ephemeral routing identities, strict memory hygiene, and a cryptographic invite system designed to prevent metadata leakage.

---

## Core Features

### Network & Anonymity
- **I2P Routing**: Uses the Simple Anonymous Messaging (SAM v3) protocol to communicate entirely within the I2P darknet.
- **Metadata Protection**: No central servers. IP addresses and connection metadata are hidden by the I2P network.
- **Dynamic & Static Identities**: 
  - *Dynamic Sessions*: Generates a disposable, burn-after-reading I2P destination for maximum anonymity.
  - *Static Sessions*: Allows persistent endpoints (Address Book) by self-encrypting the I2P destination securely on disk using the user's PGP key.

### Cryptography & Security
- **End-to-End PGP**: All messages are strictly PGP-encrypted locally before transmission.
- **Argon2 Key Protection**: PGP private keys are encrypted at rest using AES-GCM and Argon2 key derivation.
- **Cryptographic Invites**: Room destinations are shared via signed and encrypted PGP blobs.
- **Anti-Replay & Time Enforcement**: Invites use strict nonces and timestamp boundaries to prevent replay attacks.
- **Trust Model Integration**: Incoming invites are verified against the local keychain to determine the sender's trust level (Trusted, Known, Unknown).
- **Memory Hygiene**: Cryptographic operations and destinations are handled strictly in RAM using mutable bytearrays, wiped with zeros before Python garbage collection.

### User Experience
- **Terminal User Interface (TUI)**: Clean, professional CLI navigation powered by `rich` and `InquirerPy`.
- **Address Book**: Securely manage trusted contacts and their public keys.
- **Health Monitor**: Built-in system to verify I2P router status, port allocations, and SAM bridge availability.

---

## Installation

### 1. From Source (Recommended for auditability)

Clone the repository:
```bash
git clone https://github.com/Neelgrevy92/Argon-client.git
cd Argon-client
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

Run the application:
```bash
python Argon_Messenger.py
```
*Note: On the first launch, Argon will attempt to detect or install the `i2pd` router locally.*

### 2. From Release
Check the Releases tab for pre-compiled binaries (Windows x64 available).

---

## Architecture & Workflows

### The Invite System
Because I2P destinations are long Base32 strings and must be exchanged out-of-band to bootstrap a session, Argon implements a secure Invite mechanism:
1. **Export**: The host creates a room, generating a JSON blob containing the destination, timestamp, and a nonce. This blob is **signed** with the host's PGP private key and **encrypted** with the recipient's PGP public key.
2. **Import**: The recipient places the invite file (`inv_xxxx.txt`) in `storage/DEST/dynamic/`.
3. **Connect**: Upon joining, Argon automatically detects the invite, decrypts it in RAM, verifies the PGP signature against the keychain, and connects to the session. The invite is then securely deleted.

### Keychain Management
Argon relies heavily on GPG/PGP keys. 
- You must generate a keypair locally (protected by an Argon2 password).
- You must import your contact's Public Key to establish a secure room and send them invites.
- Setting an alias as `main` will set it as the default identity for automated actions.

---

## Legal & Disclaimer
Argon is provided as an open-source tool for secure communication. The developers assume no liability for misuse, data loss, or compromise. Always review the codebase and understand your threat model before relying on cryptographic software in high-risk scenarios.
