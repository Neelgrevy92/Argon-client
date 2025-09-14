# src/chat.py
import socket
import threading
import random
import string
import time
from colorama import Fore, Style
import getpass
from .encrypt import *   # decrypt_private_key, pgp_encrypt, pgp_decrypt (existing)
import os
from pgpy import PGPKey, PGPMessage
import datetime
import sys
import select

SAM_HOST = "127.0.0.1"
SAM_PORT = 7656

# ----------------- Helpers -----------------
def generate_random_id(length=8):
    """generate a random ID per session"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def recv_line(sock):
    """read a line that ends with \\n from the socket"""

    data = b''
    while True:
        ch = sock.recv(1)
        if not ch:
            return None
        data += ch
        if ch == b'\n':
            break
    return data.decode()

def send_line(sock, line):
    """Send a line that ends with \n"""

    sock.sendall((line + "\n").encode())

# --- New helper: read exact N bytes (blocking until N read or EOF) ---
def recv_exact(sock, n):
    """read exactly n octets from socket, or none if EOF"""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ----------------- SAM -----------------
def sam_hello():
    """The HELLO handshake"""
    s = socket.create_connection((SAM_HOST, SAM_PORT))
    send_line(s, "HELLO VERSION MIN=3.1 MAX=3.3")
    resp = recv_line(s)
    if not resp or "RESULT=OK" not in resp:
        raise Exception("Handshake SAM failed : " + str(resp))
    return s

def sam_dest_generate(s):
    """Generating the I2P DEST"""

    send_line(s, "DEST GENERATE SIGNATURE_TYPE=7")
    resp = b''
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        resp += chunk
        if b'\n' in resp:
            break
    resp = resp.decode().strip()
    pub = priv = None
    for line in resp.split('\n'):
        if line.startswith("DEST REPLY"):
            parts = line.split()
            for part in parts:
                if part.startswith("PUB="):
                    pub = part.split('=', 1)[1]
                elif part.startswith("PRIV="):
                    priv = part.split('=', 1)[1]
    if not pub or not priv:
        raise Exception(f"Invalid DEST GENERATE : {resp}")
    return pub, priv

def sam_create_session(s, nickname, privkey):
    '''creating the I2P session'''

    cmd = f"SESSION CREATE STYLE=STREAM ID={nickname} DESTINATION={privkey} i2cp.leaseSetEncType=4 SIGNATURE_TYPE=7"
    send_line(s, cmd)
    line = recv_line(s)
    if not line.startswith("SESSION STATUS") or "RESULT=OK" not in line:
        raise Exception("SESSION CREATE failed : " + str(line))

def sam_stream_connect(s, nickname, dest_pub):
    """Ask for A SAM connexion with the given DEST"""

    send_line(s, f"STREAM CONNECT ID={nickname} DESTINATION={dest_pub}")
    line = recv_line(s)
    if not line.startswith("STREAM STATUS") or "RESULT=OK" not in line:
        raise Exception("STREAM CONNECT failed: " + line)

def sam_stream_accept(s, nickname, timeout=30):
    """wait for an inbound connexion"""
    send_line(s, f"STREAM ACCEPT ID={nickname}")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            readable, _, _ = select.select([s], [], [], 1.0)
            if s in readable:
                line = recv_line(s)
                if line and line.startswith("STREAM STATUS"):
                    if "RESULT=OK" in line:
                        print(Fore.GREEN + "[CONECTED & ENCRYPTED]" + Style.RESET_ALL)
                        return True
                    else:
                        raise Exception(Fore.RED + "Failed STREAM ACCEPT: " + line)
        except socket.timeout:
            continue
        except Exception as e:
            raise e
    raise Exception("Timeout: No inbound connexion after 30s")

# ----------------- PGP -----------------
def encrypt_message(msg, pubkey):
    """Return the armored ASCII string"""
    encrypted = pgp_encrypt(pubkey, msg)  # on suppose pgp_encrypt retourne un PGPMessage ou string
    # Si pgp_encrypt retourne un PGPMessage (objet), on force str()
    if not isinstance(encrypted, str):
        encrypted = str(encrypted)
    return encrypted

def pgp_decrypt_message(private_key_obj, pgp_blob_bytes):
    """
    Unencrypt Armored PGP (bytes)
    private_key_obj: object PGPKey (unlocked) returned from decrypt_private_key.
    pgp_blob_bytes: bytes of the armored message.
    """
    try:
        if isinstance(pgp_blob_bytes, bytes):
            pgp_blob = pgp_blob_bytes.decode('utf-8', errors='ignore')
        else:
            pgp_blob = str(pgp_blob_bytes)
        msg_obj = PGPMessage.from_blob(pgp_blob)
        #w/ private_key_obj being a PGPKey unlocked.
        if hasattr(private_key_obj, 'decrypt'):
            clear = private_key_obj.decrypt(msg_obj)
            return str(clear.message)
        else:
            # fallback to function imported from encrypt module if exists
            return pgp_decrypt(private_key_obj, msg_obj)
    except Exception as e:
        raise

# ----------------- Binary framing protocol helpers -----------------
def send_framed_message(sock, payload_bytes):
    """
    Send: [4 bytes BE length][payload_bytes]
    This prevent TCP fragmentation bt specifing the number of bytes 
    """
    length = len(payload_bytes)
    header = length.to_bytes(4, 'big')
    sock.sendall(header + payload_bytes)

def recv_framed_message(sock):
    """
    read the header 4 bytes,
    return the bytes of the payload, or None if socket got closed.
    """
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    length = int.from_bytes(hdr, 'big')
    if length == 0:
        return b''
    data = recv_exact(sock, length)
    return data

# ----------------- Chat -----------------
def chat_session(sock, private_key_file, pubkey_remote):
    print(Fore.YELLOW + "[INFO] Acessing the encrypted PRIVKEY.." + Style.RESET_ALL)

    # Decrypt the private key once per session
    try:
        private_key = decrypt_private_key(private_key_file)
        #If the Argon2 password is correct we can use the privatekey.
        print(Fore.GREEN + "[INFO] Private Key sucessfully unlocked.\n" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[ERREUR] Unable to decrypt PRIVATE KEY: {e}" + Style.RESET_ALL)
        return

    # reception thread using the framing logic
    def receive():
        while True:
            length_bytes = sock.recv(4)
            length = int.from_bytes(length_bytes, "big")
            payload = sock.recv(length)
            try:
                try:
                    clear_text = pgp_decrypt_message(private_key, payload)
                    timestamp = time.strftime("%H:%M:%S")
                    print(Fore.MAGENTA + f"\r[{timestamp}] Remote: {clear_text}\n" + Fore.CYAN + "You: ", end='')
                except Exception as e:
                    print(Fore.GREEN + f"\nuser 2 connected" + Style.RESET_ALL) #the first SAM handshake cant be PGP ARMORED
            except Exception as e:
                print(Fore.RED + f"\n[Reception error: {e}]" + Style.RESET_ALL)
                break

    threading.Thread(target=receive, daemon=True).start()

    try:
        while True:
            msg = input(Fore.CYAN + "You: " + Style.RESET_ALL)
            if not msg:
                continue
            # Encrypt the message before sending
            try:
                armored = encrypt_message(msg, pubkey_remote)
                if isinstance(armored, str):
                    armored_bytes = armored.encode('utf-8')
                else:
                    armored_bytes = bytes(armored)
                #print(Fore.YELLOW + f"[DEBUG] encrypted message size: {len(armored_bytes)} bytes" + Style.RESET_ALL)

                # Send framed message (4 bytes length + payload)
                send_framed_message(sock, armored_bytes)
            except Exception as e:
                print(Fore.RED + f"\n[Unable to send message: {e}]" + Style.RESET_ALL)
                break

    except (KeyboardInterrupt, BrokenPipeError, OSError):
        print(Fore.YELLOW + "\n[Chat is over]" + Style.RESET_ALL)
    finally:
        try:
            sock.close()
        except:
            pass

# ----------------- Room functions -----------------
def join_room(pubkey_remote_file, private_key_file):
    """Join an exisiting I2P Destination encrypted workflow """

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    public_path = os.path.join(base_dir, "Keychain", "public", pubkey_remote_file)
    private_path = os.path.join(base_dir, "Keychain", "private", private_key_file)

    print(f"[DEBUG] Looking for public key at: {public_path}")
    print(f"[DEBUG] Looking for private key at: {private_path}")

    if not os.path.isfile(public_path):
        print(f"[ERROR] Public key not found: {public_path}")
        input('')
        return
    if not os.path.isfile(private_path):
        print(f"[ERROR] Private key not found: {private_path}")
        input('')
        return

    try:
        with open(public_path, 'r') as f:
            pubkey_remote_content = f.read()
            pubkey_remote = PGPKey.from_blob(pubkey_remote_content)[0]
        #print('extraction suceeded')
        os.system('cls')

        time.sleep(0.1)
        print(Fore.YELLOW + "Enter the target DEST :" + Style.RESET_ALL)
        dest_pub = input().strip()

        client_session_id = "client_" + generate_random_id(6)

        # Create local transient session
        s1 = sam_hello()
        pub, priv = sam_dest_generate(s1)
        sam_create_session(s1, client_session_id, priv)

        # New socket for the stream connect (this socket becomes the data pipe)
        s2 = sam_hello()
        sam_stream_connect(s2, client_session_id, dest_pub)

        print(Fore.GREEN + "[CONNECTED] - You can start chatting ! " + Style.RESET_ALL)
        chat_session(s2, private_path, pubkey_remote)

    except Exception as e:
        print(Fore.RED + f"Error while joining room: {e}" + Style.RESET_ALL)
        import traceback
        traceback.print_exc()

def create_room(private_key_file, pubkey_remote_file):
    """Create session and accept incoming users ==> encrypted workflow"""
    time.sleep(1)
    os.system("cls")
    
    #looking for the private and public keys passed 
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        private_path = os.path.join(base_dir, "Keychain", "private", private_key_file)
        public_path = os.path.join(base_dir, "Keychain", "public", pubkey_remote_file)

        if not os.path.isfile(private_path):
            print(f"[ERROR] Private key not found: {private_path}")
            input('Press enter to continue...')
            return
        if not os.path.isfile(public_path):
            print(f"[ERROR] Public key not found: {public_path}")
            input('Press enter to continue...')
            return

        with open(public_path, 'r') as f:
            pubkey_remote_content = f.read()
            pubkey_remote = PGPKey.from_blob(pubkey_remote_content)[0]


        main_session_id = "host_" + generate_random_id(6)
        print("[INFO] - CREATING ROOM for id : " + main_session_id)

        # Create I2P session & get transient dest
        s = sam_hello()
        pub, priv = sam_dest_generate(s)
        sam_create_session(s, main_session_id, priv)

        print("[SUCESS] Destination generated ! Copy the key and give it to your contact (Dont hesitate to encrypt the DEST)")
        time.sleep(1)
        os.system("cls")
        header = Fore.CYAN + rf"""DEST____________________________________________________________________________________________________________________

{pub}
________________________________________________________________________________________________________________________
    """
        print(header)
        print("waiting for inbound connexion...")

        s2 = sam_hello()
        sam_stream_accept(s2, main_session_id)
        print(Fore.GREEN + "[CONNECTED] start chatting" + Style.RESET_ALL)

        chat_session(s2, private_path, pubkey_remote)

    except Exception as e:
        print(Fore.RED + f"Error create_room: {e}" + Style.RESET_ALL)
        import traceback
        traceback.print_exc()
        input()
        return
