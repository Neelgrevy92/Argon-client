# Argon-client

Argon is a Python-based chat client built for the **I2P SAM protocol** using **i2pd** as the underlying router.  
It allows encrypted peer-to-peer communication over the I2P network, focusing on simplicity, security, and modular design.

---

## Features
- 🌍  anonymous messaging over the I2P network  
- ⚡ Lightweight Python implementation  
- 📡 Uses **SAM (Simple Anonymous Messaging)** protocol to connect with `i2pd`  
- 🖥️ CLI-based client
- 🔐 Native PGP implementation
- 🔒 All PGP privatekeys are encrypted with Argon2 

---

## Installation

### 1. Install dependencies

Install dependencies
```bash
pip install -r requirements.txt
```
Run the Client, it will setup and install the i2pd c++ router
```bash
python Argon_messenger.py
```

### 2. Main Menu options

```bash
1 - Join room      |   v - Vault       |
2 - Create room    |   x - Settings    |
3 - Keychain       |   q - Quit        |
```

1 - Join an existing I2P chat using its B32 Destination
2 - Create an I2P chat room and give you your Destination
3 - Show your Private keys and public keys and enable to add aliases --> if you use the main alias on a keypair you will be able to skip the Keypair selection
v - Soon
x - General settings, you can deactivate PGP encryption here at your own risk
q - quit the program
h - health can be used to check the health of the I2P routing
i - Info and guide 


