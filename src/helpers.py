from colorama import Fore, Style, init
init(autoreset=True)
import csv
import configparser
import subprocess
from pgpy import PGPKey, PGPMessage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import os
import getpass
import warnings
from cryptography.utils import CryptographyDeprecationWarning


SETTINGS_FILE = "./settings.ini"

def is_i2p_encryption_enabled():
    """Check if I2P encryption is enabled in settings"""
    config = configparser.ConfigParser()
    
    try:
        config.read(SETTINGS_FILE)
        
        # Check if section and key exist - CORRECTED!
        if ('I2P Network' in config and 
            'encrypt_i2p_comm' in config['I2P Network']):
            
            encrypt_setting = config['I2P Network']['encrypt_i2p_comm']
            return encrypt_setting.lower() == 'true'
        
        # Return True by default if parameter doesn't exist
        return True
        
    except Exception as e:
        print(f"Error reading settings.ini: {e}")
        # Return True by default in case of error
        return True

def argon_protect(private_key_file, output_file):
    """Protects private key by encrypting it with user password"""
    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()
    
    password = getpass.getpass("Enter your secret: ").encode()

    salt = os.urandom(16)
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

    print(Fore.GREEN + f"[SUCCESS] - PRIVATEKEY stored at {output_file}")

def find_keys_by_alias(alias):
    """Finds keys with a specific alias"""
    private_key = None
    public_key = None
    
    try:
        with open('./Keychain/register.csv', 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            
            for row in reader:
                if row['Alias'] == alias:
                    if row['Type'] == 'private':
                        private_key = row['Filename']
                    elif row['Type'] == 'public':
                        public_key = row['Filename']
        
        return {'private': private_key, 'public': public_key}
        
    except FileNotFoundError:
        print(Fore.RED + "[ERROR] - Keychain file not found!")
        return {'private': None, 'public': None}
    except Exception as e:
        print(Fore.RED + f"[ERROR] - Reading keychain: {e}")
        return {'private': None, 'public': None}

def handle_missing_key_files(private_key, public_key):
    """Handles missing key files"""
    print(Fore.RED + "[ERROR] - Key files not found!")
    if private_key and not os.path.exists(os.path.join('./Keychain', private_key)):
        print(Fore.RED + f"Missing private key: {private_key}")
    if public_key and not os.path.exists(os.path.join('./Keychain', public_key)):
        print(Fore.RED + f"Missing public key: {public_key}")

def handle_missing_main_alias(private_key, public_key):
    """Handles absence of keys with 'main' alias"""
    print(Fore.RED + "[ERROR] - No keypair with alias 'main' found!")
    if not private_key:
        print(Fore.RED + "Missing private key with alias 'main'")
    if not public_key:
        print(Fore.RED + "Missing public key with alias 'main'")
    

    print(Fore.YELLOW + "Please select keys manually or create a keypair with alias 'main'")
