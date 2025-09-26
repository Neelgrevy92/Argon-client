from colorama import Fore, Back, Style
from colorama import init
init(autoreset=True)
import os 
import subprocess
import time
import threading
import shutil
import csv
# encryption
from pgpy import PGPKey, PGPMessage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import os
import getpass
import sys


from src.browser import registry_to_file
from src.website_helper import *



from src.keychain import cli_keychain
from src.settings import setting_cli
from src.settings import i2p_health
from src.settings import ensure_settings_exists
from src.guide import *

from src.ecchat import join_room
from src.ecchat import create_room
from src.unsafe.chat import run_server, run_client


from src.installer import check_files
from src.helpers import *


SETTINGS_FILE = "./settings.ini"


title = r"""________________________________________________________________________________________________________________________
    ___                              _________            __ 
   /   |  _________ _____  ____     / ____/ (_)__  ____  / /_
  / /| | / ___/ __ `/ __ \/ __ \   / /   / / / _ \/ __ \/ __/
 / ___ |/ /  / /_/ / /_/ / / / /  / /___/ / /  __/ / / / /_  
/_/  |_/_/   \__, /\____/_/ /_/   \____/_/_/\___/_/ /_/\__/  
            /____/                                           
________________________________________________________________________________________________________________________

Version : 1.0.2   -h health -i general info
________________________________________________________________________________________________________________________

"""

menu = """                               
                                        |   1 - Join room     |   4 - web       |
                                        |   2 - Create room   |   v - Vault     |
                                        |   3 - Keychain      |   x - Settings  |

"""


def display_keychain():
    """Display the keychain from CSV file"""
    try:
        with open('./Keychain/register.csv', 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Separate private and public keys
            private_keys = []
            public_keys = []
            
            for row in reader:
                if row['Type'] == 'private':
                    private_keys.append(row)
                elif row['Type'] == 'public':
                    public_keys.append(row)
            
            # Display private keys
            print(Fore.YELLOW + "------[PRIVATE]--------")
            for key in private_keys:
                alias = key['Alias'] if key['Alias'] else key['Filename']
                print(f"{key['ID']} - {alias}")
            
            # Display public keys
            print(Fore.GREEN + "------[PUBLIC]---------")
            for key in public_keys:
                alias = key['Alias'] if key['Alias'] else key['Filename']
                print(f"{key['ID']} - {alias}")
            
            print(Fore.RESET)
            
    except FileNotFoundError:
        print(Fore.RED + "Keychain file not found!")
        print(Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"Error reading keychain: {e}")
        print(Fore.RESET)

def get_key_filename(key_id, key_type):
    """Get filename for a given key ID and type"""
    try:
        with open('./Keychain/register.csv', 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['ID'] == key_id and row['Type'] == key_type:
                    return row['Filename']
        return None
    except:
        return None



def main():
    """
    Main entry point for the Argon I2P Message Service application.
    Handles initialization, dependency checks, and provides the main menu interface.
    """
    os.system(r'title checking Argon / I2P config ...')
    os.system(r'cls')

    # Check if i2pd is installed
    installed = check_files()
    
    if not installed:
        print(Fore.RED + "[FATAL] - i2pd is required but not installed. The application cannot continue.")
        print(Fore.RED + "Please install i2pd manually and restart the application.")
        input("Press Enter to exit...")
        sys.exit(1)  
    else:
        print(Fore.GREEN + "[SUCCESS] - All dependencies are ready!")

    # Check if i2pd is running
    result = subprocess.run(
        ['powershell', 'Get-Process i2pd -ErrorAction SilentlyContinue'],
        capture_output=True,
        text=True
    )

    if result.stdout.strip() != "":
        print(Style.DIM + '[INFO] - I2P router already running, SAM service available. Proceeding...')
        print(Fore.YELLOW + r"[WARNING] - We recommend resetting the router after each use /!\ risk of fingerprinting and RAM extraction")
    else:
        print('Starting a new I2P router...')
        # Launch it 
        subprocess.Popen(['.\\i2pd.exe'])
    
    time.sleep(1)

    # Check if there are any keys that need to be handled
    KEY_EXTENSIONS = ['.asc', '.gpg', '.bin', '.key']
    root = os.getcwd()

    for file in os.listdir(root):
        filepath = os.path.join(root, file)
        if os.path.isfile(filepath) and any(file.lower().endswith(ext) for ext in KEY_EXTENSIONS):
            if file.lower().endswith('.asc'):
                if 'public' in file.lower():
                    print(Fore.YELLOW + f"[WARNING] - Misplaced PUBKEY: {file} move to ==> ./Keychain/public")
                    dest = os.path.join('./Keychain/public', file)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.move(filepath, dest)
                elif 'secret' in file.lower() or 'private' in file.lower():
                    print(Fore.RED + f"[WARNING!] - Misplaced PRIVATE KEY, high risk: {file}")
                    time.sleep(1)
                    print('[INFO] - Continuing to encryption manager...')
                    dest_file = os.path.join("./Keychain/private", file + ".bin")
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    argon_protect(filepath, dest_file)
                    os.remove(filepath)  # delete the old .asc after protection
                    print("[INFO] - Make sure to bind your Privatekey to an alias in the keypair manager (3)!")
            elif file.lower().endswith('.bin'):
                print(f'[WARNING] - Misplaced encrypted privatekey? {file} move to ==> ./Keychain/private')
                dest = os.path.join('./Keychain/private', file)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.move(filepath, dest)
                print("[INFO] - Make sure to bind your Privatekey to an alias in the Vault (v)!")
            else:
                print("Currently we can't process those encryption methods automatically, please dispose of your keys.")
  
    # Check if the .ini config file exists
    ensure_settings_exists()

    print('[INFO] - Welcome Back')

    while True:
        os.system(r'title ARGON I2P MESSAGE SERVICE')
        os.system(r'cls')
        print(Fore.CYAN + title)
        print(menu)
        choice = input(">>>").lower()

        if choice == "3":
            cli_keychain()

        if choice == "1":
            if is_i2p_encryption_enabled():
                pass
            else:
                print("I2P encryption is DISABLED")
                print("[WARNING] - NO ENCRYPTION WILL BE USED IN THIS CONVERSATION")
                print("[WARNING] - If this is an error, go to settings and set 'encrypt_i2p_comm = true'")
                print("[INFO] - Make sure your contact has also disabled encrypted comms if you want to use this mode")
                print("Else continue by clicking enter...")
                input()
                run_client()

            print("Please choose the PRIVATEKEY and PUBLICKEY or i for info")
            print('type 1001/2001 for instance')
            
            # Display available keys
            display_keychain()
            
            choice = input(">>>")
            if choice == "i":
                os.system(r'cls')
                os.system(r'title ARGON CLIENT - INFORMATION CENTER - KEYS FOR COMMUNICATION ')
                print(Fore.CYAN + "________________________________________________________________________________________________________________________")
                print(Fore.CYAN + '[INFORMATION] - PGP KEYS for communication')
                print(Fore.CYAN + "________________________________________________________________________________________________________________________\n")
                
                print('- Currently the only way to communicate on Argon client is to use GNUPG keys.')
                print('- Send your public key to your contact => they will save it in their keychain ./keychain/public - they can add an alias to it so you can use the same keys next time')
                print('- Same for you, you should get their pub key and choose it for communication')
                print(Fore.YELLOW + '- NEVER SHARE YOUR PRIVATEKEY - We ask for your privatekey only to decrypt incoming conversations in RAM, never in clear HDD/SSD')
                print('- This is why we need your user password to decrypt the privatekey before being able to process it for the duration of the communication.')
                print("- For more info on KEYS, use the same command in the keychain.\n")
                input('...')
                continue
            
            if choice == "":
                print('[INFO] Running default KEYPAIR alias = "main"')
                
                # Check if Keychain directories exist
                keychain_dir = 'Keychain'
                private_dir = os.path.join(keychain_dir, 'private')
                public_dir = os.path.join(keychain_dir, 'public')
                
                if not os.path.exists(keychain_dir):
                    print(Fore.RED + f"[ERROR] - Keychain directory not found: {os.path.abspath(keychain_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                if not os.path.exists(private_dir):
                    print(Fore.RED + f"[ERROR] - Private key directory not found: {os.path.abspath(private_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                if not os.path.exists(public_dir):
                    print(Fore.RED + f"[ERROR] - Public key directory not found: {os.path.abspath(public_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                # Check if keys with 'main' alias exist
                main_keys = find_keys_by_alias('main')
                
                if main_keys['private'] and main_keys['public']:
                    # Build correct paths
                    privkey_path = os.path.join(private_dir, main_keys['private'])
                    pubkey_path = os.path.join(public_dir, main_keys['public'])
                    
                    print(Fore.YELLOW + f"[DEBUG] - Private key path: {os.path.abspath(privkey_path)}")
                    print(Fore.YELLOW + f"[DEBUG] - Public key path: {os.path.abspath(pubkey_path)}")
                    
                    if os.path.exists(privkey_path) and os.path.exists(pubkey_path):
                        print(f"[INFO] - Using private key: {main_keys['private']}")
                        print(f"[INFO] - Using public key: {main_keys['public']}")
                        # Pass only filenames, not full paths
                        join_room(main_keys['public'], main_keys['private'])
                                    
            # Private key selection by ID 
            try:
                IDS = choice.split("/")
                if len(IDS) != 2:
                    print(Fore.RED + "Please provide both private and public key IDs separated by /")
                    input('Press enter to continue...')
                    continue
                    
                privkey_id = IDS[0].strip()
                pubkey_id = IDS[1].strip()
                
                # Check if keys exist in the CSV file
                privkey_filename = get_key_filename(privkey_id, 'private')
                pubkey_filename = get_key_filename(pubkey_id, 'public')
                
                if not privkey_filename:
                    print(Fore.RED + f"Private key with ID {privkey_id} not found!")
                    input('Press enter to continue...')
                    continue
                    
                if not pubkey_filename:
                    print(Fore.RED + f"Public key with ID {pubkey_id} not found!")
                    input('Press enter to continue...')
                    continue
                
                print(Fore.GREEN + f"Selected keys: Private={privkey_filename}, Public={pubkey_filename}")
                
                join_room(pubkey_filename, privkey_filename)
                
                input('Press enter to continue...')
                
            except Exception as e:
                print(Fore.RED + f"Error processing key selection: {e}")
                input('Press enter to continue...')

        if choice == "2":  # Create Room
            if is_i2p_encryption_enabled():
                pass
            else:
                print("I2P encryption is DISABLED")
                print("[WARNING] - NO ENCRYPTION WILL BE USED IN THIS CONVERSATION")
                print("[WARNING] - If this is an error, go to settings and set 'encrypt_i2p_comm = true'")
                print("[INFO] - Make sure your contact has also disabled encrypted comms if you want to use this mode")
                print("Else continue by clicking enter...")
                input()
                run_server()

            print(Fore.CYAN + "Please choose your PRIVATEKEY and the recipient's PUBLICKEY or i for info")
            print('type 1001/2001 for keypair select | Hit enter if you want to use default keys | hit x for non encrypted comms')
            
            # Display available keys
            display_keychain()
            
            choice = input(">>>")
            if choice == "i":
                os.system(r'cls')
                os.system(r'title ARGON CLIENT - INFORMATION CENTER - KEYS FOR COMMUNICATION ')
                print(Fore.CYAN + "________________________________________________________________________________________________________________________")
                print(Fore.CYAN + '[INFORMATION] - PGP KEYS for communication')
                print(Fore.CYAN + "________________________________________________________________________________________________________________________\n")
                
                print(Fore.YELLOW + '-You can and you should use GNUPG keys to communicate on this I2P client ==> if you still dont want to be secure go into settings and change the encrypt_i2p_comm parameter')
                print('- Send your public key to your contact => he will save it in his keychain ./keychain/public - he will be able to add an alias to it so you can use the same keys next time')
                print('- Same for you you should get his pub key and choose it for the communication')
                print(Fore.YELLOW + '- NEVER SHARE YOUR PRIVATEKEY - We ask your privatekey only to decrypt the incoming conversation on the RAM, never in clear HDD/SSD')
                print('- This is why we will need your user password to decrypt the privatekey before being able to process it for the duration of the communication.')
                print(Fore.YELLOW + '-If you have configurated an alias as main for one public key and one private key you can just hit enter and it will use the keypair')
                print("- For more infos on the KEYS use the same command in the keychain.\n")
                input('...')
                continue

            if choice == "":
                print('[INFO] Running default KEYPAIR alias = "main"')
                
                # Check if Keychain directories exist
                keychain_dir = 'Keychain'
                private_dir = os.path.join(keychain_dir, 'private')
                public_dir = os.path.join(keychain_dir, 'public')
                
                if not os.path.exists(keychain_dir):
                    print(Fore.RED + f"[ERROR] - Keychain directory not found: {os.path.abspath(keychain_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                if not os.path.exists(private_dir):
                    print(Fore.RED + f"[ERROR] - Private key directory not found: {os.path.abspath(private_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                if not os.path.exists(public_dir):
                    print(Fore.RED + f"[ERROR] - Public key directory not found: {os.path.abspath(public_dir)}")
                    input("Press Enter to continue...")
                    continue
                
                # Check if keys with 'main' alias exist
                main_keys = find_keys_by_alias('main')
                
                if main_keys['private'] and main_keys['public']:
                    # Build correct paths
                    privkey_path = os.path.join(private_dir, main_keys['private'])
                    pubkey_path = os.path.join(public_dir, main_keys['public'])
                    
                    print(Fore.YELLOW + f"[DEBUG] - Private key path: {os.path.abspath(privkey_path)}")
                    print(Fore.YELLOW + f"[DEBUG] - Public key path: {os.path.abspath(pubkey_path)}")
                    
                    if os.path.exists(privkey_path) and os.path.exists(pubkey_path):
                        print(f"[INFO] - Using private key: {main_keys['private']}")
                        print(f"[INFO] - Using public key: {main_keys['public']}")
                        # Pass only filenames, not full paths
                        create_room(main_keys['private'], main_keys['public'])

            try:
                IDS = choice.split("/")
                if len(IDS) != 2:
                    print(Fore.RED + "Please provide both private and public key IDs separated by /")
                    input('Press enter to continue...')
                    continue
                    
                privkey_id = IDS[0].strip()
                pubkey_id = IDS[1].strip()
                
                privkey_filename = get_key_filename(privkey_id, 'private')
                pubkey_filename = get_key_filename(pubkey_id, 'public')
                
                if not privkey_filename:
                    print(Fore.RED + f"Private key with ID {privkey_id} not found!")
                    input('Press enter to continue...')
                    continue
                    
                if not pubkey_filename:
                    print(Fore.RED + f"Public key with ID {pubkey_id} not found!")
                    input('Press enter to continue...')
                    continue
                    
                print(Fore.GREEN + f"Selected keys: Private={privkey_filename}, Public={pubkey_filename}")
                create_room(privkey_filename, pubkey_filename)

            except Exception as e:
                print(Fore.RED + f"Error processing key selection: {e}")
                input('Press enter to continue...')

        if choice == "x":
            setting_cli()

        if choice == "h":
            i2p_health()


        if choice == '4':
            print("1 - browse internet")
            print("2 - Host website")
            print('3 - Download safely i2p registery')
            
            choice = input('choose')

            if choice=="3":
                pass
                #registry_to_file("./storage/i2p_registery.csv")
            if choice=="2":
                host_website()
                input()

            input()
        if choice == "i":
            guide()

main()