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
from .helpers import clear_screen, set_terminal_title
from .tui import render_dest_display, render_chat_header, render_success, render_info, render_error, console, wait_for_enter

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

# ----------------- Chat input with Ctrl+Q menu ─────────────────
def _chat_input(prompt):
    """
    Custom character-by-character input that intercepts Ctrl+Q.
    Returns the typed string on Enter, or None when Ctrl+Q is pressed.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars = []

    if os.name == 'nt':
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch == '\x11':          # Ctrl+Q
                sys.stdout.write('\n')
                sys.stdout.flush()
                return None
            elif ch == '\r':          # Enter
                sys.stdout.write('\n')
                sys.stdout.flush()
                return ''.join(chars)
            elif ch == '\x08':        # Backspace
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == '\x03':        # Ctrl+C
                raise KeyboardInterrupt
            elif ch in ('\x00', '\xe0'):  # special keys (arrows etc)
                msvcrt.getwch()       # consume second byte
            else:
                chars.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == '\x11':      # Ctrl+Q
                    sys.stdout.write('\r\n')
                    sys.stdout.flush()
                    return None
                elif ch in ('\r', '\n'):
                    sys.stdout.write('\r\n')
                    sys.stdout.flush()
                    return ''.join(chars)
                elif ch in ('\x7f', '\x08'):  # Backspace
                    if chars:
                        chars.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif ch == '\x03':    # Ctrl+C
                    raise KeyboardInterrupt
                elif ch == '\x1b':    # Escape sequence
                    sys.stdin.read(2)
                else:
                    chars.append(ch)
                    sys.stdout.write(ch)
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def show_chat_menu():
    """In-chat action menu triggered by Ctrl+Q"""
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator
    from .tui import INQUIRER_STYLE

    choices = [
        {"name": "  Send audio message", "value": "audio"},
        {"name": "  Send file", "value": "file"},
        Separator(),
        {"name": "  <- Back to chat", "value": "cancel"},
    ]

    action = inquirer.select(
        message="Action",
        choices=choices,
        pointer=">",
        qmark=">>",
        instruction="(arrows to navigate, Enter to select)",
        style=INQUIRER_STYLE,
    ).execute()

    return action


# ----------------- Chat -----------------
def chat_session(sock, private_key_file, pubkey_remote):
    render_info("Accessing encrypted PRIVKEY...")

    # Decrypt the private key once per session
    try:
        private_key = decrypt_private_key(private_key_file)
        #If the Argon2 password is correct we can use the privatekey.
        render_success("Private Key successfully unlocked")
    except Exception as e:
        render_error(f"Unable to decrypt PRIVATE KEY: {e}")
        return

    # reception thread using the framing logic
    def receive():
        peer_connected = False
        while True:
            try:
                length_bytes = sock.recv(4)
                if not length_bytes or len(length_bytes) < 4:
                    render_info("Connection closed by remote")
                    break
                length = int.from_bytes(length_bytes, "big")
                if length <= 0 or length > 1_000_000:  # sanity check
                    continue
                payload = recv_exact(sock, length)
                if not payload:
                    render_info("Connection closed by remote")
                    break

                try:
                    clear_text = pgp_decrypt_message(private_key, payload)
                    timestamp = time.strftime("%H:%M:%S")
                    print(Fore.MAGENTA + f"\r[{timestamp}] Remote: {clear_text}\n" + Fore.CYAN + "You: ", end='')
                except Exception:
                    # First failed decrypt = SAM handshake, show connected once
                    if not peer_connected:
                        peer_connected = True
                        render_success("Peer connected")
                    # Subsequent failed decrypts are silently ignored
                    # (own messages echoed back, malformed data, etc.)

            except (ConnectionResetError, ConnectionAbortedError, OSError):
                render_info("Connection lost")
                break
            except Exception as e:
                print(Fore.RED + f"\n[Reception error: {e}]" + Style.RESET_ALL)
                break

    threading.Thread(target=receive, daemon=True).start()

    render_chat_header(True)
    try:
        while True:
            msg = _chat_input("\033[96mYou: \033[0m")

            if msg is None:
                # Ctrl+Q was pressed -> show action menu
                action = show_chat_menu()
                if action == "audio":
                    render_info("Audio message: not yet implemented")
                elif action == "file":
                    render_info("File transfer: not yet implemented")
                # "cancel" -> back to chat
                continue

            if not msg:
                continue
            # Encrypt the message before sending
            try:
                armored = encrypt_message(msg, pubkey_remote)
                if isinstance(armored, str):
                    armored_bytes = armored.encode('utf-8')
                else:
                    armored_bytes = bytes(armored)

                # Send framed message (4 bytes length + payload)
                send_framed_message(sock, armored_bytes)
            except Exception as e:
                print(Fore.RED + f"\n[Unable to send message: {e}]" + Style.RESET_ALL)
                break

    except (KeyboardInterrupt, BrokenPipeError, OSError):
        render_info("Chat session ended")
    finally:
        try:
            sock.close()
        except:
            pass

# ----------------- Room functions -----------------

# ----------------- Room functions -----------------
def join_room(pubkey_remote_file, private_key_file):
    """Join an existing I2P Destination — invite-aware encrypted workflow"""
    from .invites import check_dynamic_invites, load_address_book
    from .tui import text_prompt, INQUIRER_STYLE
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator
    import gc

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    public_path  = os.path.join(base_dir, "Keychain", "public",  pubkey_remote_file)
    private_path = os.path.join(base_dir, "Keychain", "private", private_key_file)

    if not os.path.isfile(public_path):
        render_error(f"Public key not found: {public_path}")
        return
    if not os.path.isfile(private_path):
        render_error(f"Private key not found: {private_path}")
        return

    try:
        with open(public_path, 'r') as f:
            pubkey_remote = PGPKey.from_blob(f.read())[0]

        clear_screen()

        # ── Step 1: decrypt private key once (needed for invite parsing)
        from .encrypt import decrypt_private_key
        render_info("Unlocking private key for invite verification...")
        try:
            priv_key_obj = decrypt_private_key(private_path)
        except Exception as e:
            render_error(f"Failed to unlock private key: {e}")
            return

        # ── Step 2: Scan dynamic invites ─────────────────────────────
        dest_ba = check_dynamic_invites(priv_key_obj)

        # ── Step 3: Fallback menu if no dynamic invite was accepted ──
        if dest_ba is None:
            choices = [
                {"name": "  Paste DEST manually", "value": "paste"},
                {"name": "  Address Book (saved contacts)", "value": "book"},
                Separator(),
                {"name": "  <- Cancel", "value": "cancel"},
            ]
            action = inquirer.select(
                message="How do you want to connect?",
                choices=choices,
                pointer=">",
                qmark=">>",
                instruction="(arrows to navigate, Enter to select)",
                style=INQUIRER_STYLE,
            ).execute()

            if action == "cancel":
                render_info("Join cancelled.")
                return

            elif action == "paste":
                raw = text_prompt("Enter the target I2P Destination", qmark=">").strip()
                if not raw:
                    render_error("No destination entered.")
                    return
                dest_ba = bytearray(raw.encode("utf-8"))

            elif action == "book":
                dest_ba = load_address_book(priv_key_obj)
                if dest_ba is None:
                    render_info("No contact selected.")
                    return

        # ── Step 4: Connect using DEST from bytearray ─────────────────
        try:
            dest_str = dest_ba.decode("utf-8")

            client_session_id = "client_" + generate_random_id(6)

            s1 = sam_hello()
            pub, priv = sam_dest_generate(s1)
            sam_create_session(s1, client_session_id, priv)

            s2 = sam_hello()
            sam_stream_connect(s2, client_session_id, dest_str)

            render_success("Connected! You can start chatting")

        finally:
            # Wipe DEST from memory regardless of what happens
            dest_ba[:] = b'\x00' * len(dest_ba)
            del dest_ba, dest_str
            gc.collect()

        chat_session(s2, private_path, pubkey_remote)

    except Exception as e:
        render_error(f"Error joining room: {e}")
        import traceback
        traceback.print_exc()


def create_room(private_key_file, pubkey_remote_file):
    """Create session and accept incoming users ==> encrypted workflow"""
    time.sleep(1)
    clear_screen()
    
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

        from InquirerPy import inquirer
        from .tui import INQUIRER_STYLE
        from .encrypt import decrypt_private_key
        
        room_type = inquirer.select(
            message="Room Type:",
            choices=[
                {"name": "  Dynamic Room (Disposable / Burn-after-reading)", "value": "dynamic"},
                {"name": "  Static Room (Persistent Identity / Address Book)", "value": "static"}
            ],
            pointer=">",
            qmark=">>",
            style=INQUIRER_STYLE
        ).execute()

        main_session_id = "host_" + generate_random_id(6)
        render_info(f"Creating room for session: {main_session_id}")

        priv_key_obj = None

        if room_type == "static":
            from .i2p_identity import get_or_create_static_i2p_dest
            render_info("Unlocking private key to access static identity...")
            priv_key_obj = decrypt_private_key(private_path)
            
            from .keychain import load_register
            entries = load_register()
            alias = "Host"
            for e in entries:
                if e["Type"] == "private" and e["Filename"] == private_key_file:
                    alias = e["Alias"] or "Host"
                    break
            
            pub, priv = get_or_create_static_i2p_dest(priv_key_obj, priv_key_obj.pubkey, alias)
            
            s = sam_hello()
            sam_create_session(s, main_session_id, priv)
        else:
            s = sam_hello()
            pub, priv = sam_dest_generate(s)
            sam_create_session(s, main_session_id, priv)

        render_success("Destination generated!")
        time.sleep(0.5)
        clear_screen()
        render_dest_display(pub)
        console.print()

        while True:
            action = inquirer.select(
                message="Room Options",
                choices=[
                    {"name": "  Start waiting for inbound connection", "value": "listen"},
                    {"name": "  Generate PGP Signed Invite", "value": "invite"},
                    {"name": "  Cancel room", "value": "cancel"}
                ],
                pointer=">",
                qmark=">>",
                style=INQUIRER_STYLE,
            ).execute()

            if action == "cancel":
                render_info("Room cancelled.")
                return

            elif action == "invite":
                from .invites import export_invite
                from .keychain import load_register

                try:
                    if priv_key_obj is None:
                        render_info("Unlocking private key to sign the invite...")
                        priv_key_obj = decrypt_private_key(private_path)

                    entries = load_register()
                    sender_alias = "Host"
                    for e in entries:
                        if e["Type"] == "private" and e["Filename"] == private_key_file:
                            sender_alias = e["Alias"] or "Host"
                            break

                    export_invite(
                        sender_priv_key=priv_key_obj,
                        sender_alias=sender_alias,
                        sender_fingerprint=priv_key_obj.fingerprint,
                        recipient_pub_key=pubkey_remote,
                        dest=pub,
                        invite_type=room_type
                    )
                except Exception as e:
                    render_error(f"Failed to generate invite: {e}")

            elif action == "listen":
                break

        render_info("Waiting for inbound connection...")

        s2 = sam_hello()
        sam_stream_accept(s2, main_session_id)
        render_success("Contact connected! Start chatting")

        chat_session(s2, private_path, pubkey_remote)

    except Exception as e:
        render_error(f"Error creating room: {e}")
        import traceback
        traceback.print_exc()
        input()
        return
