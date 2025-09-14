from pgpy import PGPKey, PGPMessage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import os
import getpass
import warnings
from cryptography.utils import CryptographyDeprecationWarning



warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)



# ===================== Fonctions =====================

def pgp_encrypt(pubkey, message):
    """Encrypt a string with PGP"""
    message_obj = PGPMessage.new(message)
    encrypted_message = pubkey.encrypt(message_obj)
    return encrypted_message

def pgp_decrypt_message(private_key, encrypted_data):
    """Decrypt a PGP message with a private key IN MEM"""
    try:
        # Method 1 with bytes
        try:
            encrypted_message = PGPMessage.from_blob(encrypted_data)
            decrypted = private_key.decrypt(encrypted_message)
            return str(decrypted.message)
        except:
            pass
        
        # Method 2 with string
        try:
            if isinstance(encrypted_data, bytes):
                encrypted_str = encrypted_data.decode('utf-8', errors='ignore')
            else:
                encrypted_str = str(encrypted_data)
            
            encrypted_message = PGPMessage.from_blob(encrypted_str)
            decrypted = private_key.decrypt(encrypted_message)
            return str(decrypted.message)
        except:
            pass
        
        # Last method try to clean
        try:
            if isinstance(encrypted_data, bytes):
                # Null bytes ?
                cleaned_data = encrypted_data.replace(b'\x00', b'').strip()
                encrypted_message = PGPMessage.from_blob(cleaned_data)
                decrypted = private_key.decrypt(encrypted_message)
                return str(decrypted.message)
            else:
                cleaned_data = str(encrypted_data).replace('\x00', '').strip()
                encrypted_message = PGPMessage.from_blob(cleaned_data)
                decrypted = private_key.decrypt(encrypted_message)
                return str(decrypted.message)
        except Exception as e:
            raise Exception(Fore.RED + f"[ERROR] - All decryption method failed... {e}")
            
    except Exception as e:
        raise Exception(f"[ERROR] - unable to decrypt {e}")


def decrypt_private_key(private_key_path):
    """Decrypt the PRIVATEKEY w/ Argon2 + AES encryption."""
    with open(private_key_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    password = getpass.getpass("Please enter your secret : ").encode()

    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.I
    )

    aesgcm = AESGCM(key)
    private_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    private_key = PGPKey.from_blob(private_key_bytes.decode())[0]

    # Nettoyage mémoire
    del private_key_bytes
    import gc
    gc.collect()
    return private_key

def argon_protect(private_key_file, output_file):
    """Argon2 method"""
    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()
    
    password = getpass.getpass("Please enter your secret : ").encode()

    salt = os.urandom(16) #this could be tweaked to improve bruteforce resilience ==> switching to Argon2id could be good (RAM protection)
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.I
    )

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_key = aesgcm.encrypt(nonce, private_key_bytes, None)

    with open(output_file, "wb") as f:
        f.write(salt + nonce + encrypted_key)

    print(f"AES encyrpted PGP key in {output_file}")
