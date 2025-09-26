from pgpy import PGPKey, PGPMessage, PGPUID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import os
import getpass
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from colorama import Fore, Back, Style
from colorama import init


from datetime import datetime


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





# ----- nouvelle version de generate_keypair (utilise PRIVATE_DIR / PUBLIC_DIR) -----
def generate_keypair(name: str, email: str):
    PUBLIC_DIR = "./Keychain/public"
    PRIVATE_DIR = "./Keychain/private"

    """
    Génère une paire PGP (clé privée non protégée) et écrit :
     - public  -> PUBLIC_DIR/<email>_public_<ts>.asc
     - private -> PRIVATE_DIR/<email>_private_<ts>.asc

    Retourne (private_key_obj, public_key_obj, private_path, public_path)
    """
    # crée les dossiers si nécessaire (les constantes PRIVATE_DIR / PUBLIC_DIR sont définies en haut du fichier)
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    os.makedirs(PRIVATE_DIR, exist_ok=True)

    # Génération simple : RSA 2048
    primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

    uid = PGPUID.new(name, email=email)

    primary.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP]
    )

    primary.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})

    # noms de fichiers basés sur l'email + timestamp pour éviter collisions
    safe_email = email.replace("@", "_at_").replace(".", "_")
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    private_filename = f"{safe_email}_private_{ts}.asc"
    public_filename = f"{safe_email}_public_{ts}.asc"

    private_path = os.path.join(PRIVATE_DIR, private_filename)
    public_path = os.path.join(PUBLIC_DIR, public_filename)

    # écrire fichiers ASCII-armored
    with open(private_path, "w", encoding="utf-8") as f:
        f.write(str(primary))

    with open(public_path, "w", encoding="utf-8") as f:
        f.write(str(primary.pubkey))

    print(Fore.GREEN + f"PRIVKEY written : {private_path}")
    print(Fore.GREEN + f"PUBKEY written : {public_path}")

    return primary, primary.pubkey, private_path, public_path