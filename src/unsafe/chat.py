import socket
import threading
import random
import string
import time
import os


from colorama import Fore, Style, init
init(autoreset=True)



#Your IP:PORT of the i2pd router
SAM_HOST = "127.0.0.1"
SAM_PORT = 7656

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

def sam_hello():
    """Open a SAM connexion and do the HELLO handshake protocol"""
    s = socket.create_connection((SAM_HOST, SAM_PORT))
    send_line(s, "HELLO VERSION MIN=3.1 MAX=3.3")
    resp = recv_line(s)
    if not resp or "RESULT=OK" not in resp:
        raise Exception("Failed SAM handshake" + str(resp))
    return s

def sam_dest_generate(s):
    """Gen the DEST with the SAM router"""
    send_line(s, "DEST GENERATE SIGNATURE_TYPE=7")
    
    # waiting for DEST REPLY
    resp = b''
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        resp += chunk
        if b'\n' in resp:
            break
    
    resp = resp.decode().strip()
    lines = resp.split('\n')
    
    pub = None
    priv = None
    
    for line in lines:
        if line.startswith("DEST REPLY"):
            parts = line.split()
            for part in parts:
                if part.startswith("PUB="):
                    pub = part.split('=', 1)[1]
                elif part.startswith("PRIV="):
                    priv = part.split('=', 1)[1]
    
    if not pub or not priv:
        raise Exception(Fore.RED + f"Invalid response for DEST GENERATE: {resp}")
    
    return pub, priv

def sam_create_session(s, nickname, privkey):
    """Create a stream session using the privatekey"""
    cmd = f"SESSION CREATE STYLE=STREAM ID={nickname} DESTINATION={privkey} i2cp.leaseSetEncType=4 SIGNATURE_TYPE=7"
    send_line(s, cmd)
    line = recv_line(s)
    if not line.startswith("SESSION STATUS") or "RESULT=OK" not in line:
        raise Exception("Failed SESSION CREATE: " + str(line))
    return

def sam_stream_connect(s, nickname, dest_pub):
    """Ask for A SAM connexion with the given DEST"""

    send_line(s, f"STREAM CONNECT ID={nickname} DESTINATION={dest_pub}")
    line = recv_line(s)
    if not line.startswith("STREAM STATUS"):
        raise Exception("Pas de réponse STREAM STATUS: " + str(line))
    if "RESULT=OK" not in line:
        raise Exception("Failed STREAM CONNECT: " + line)
    return

def sam_stream_accept(s, nickname):
    """Wait for a STREAM ACCEPT connexion"""
    send_line(s, f"STREAM ACCEPT ID={nickname}")
    line = recv_line(s)
    if not line.startswith("STREAM STATUS"):
        raise Exception("No response STREAM STATUS: " + str(line))
    if "RESULT=OK" not in line:
        raise Exception("Failed STREAM ACCEPT: " + line)
    return

def chat_session(sock):
    """Launch the chat logic : I/O treaded on sock."""
    def receive():
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print(FORE.RED + "\n[Connexion closed]")
                    break
                print("\rUser2: " + data.decode() + Fore.CYAN + "\nYou: ", end='')
            except:
                print("\n[Connexion aborted]")
                break

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()

    try:
        while True:
            msg = input(Fore.CYAN + "You: ")
            if not msg: 
                continue
            try:
                sock.sendall(msg.encode())
            except:
                print(Fore.RED + "\n[Unable to send the message]")
                break
    except (BrokenPipeError, OSError, KeyboardInterrupt):
        print("\n[CHAT ENDED]")
    finally:
        try:
            sock.close()
        except:
            pass

def run_server():
    """Create session and accept incoming users"""
    os.system('cls')
    os.system('title ARGON UNENCRYPTED COMMUNICATION')

    try:

        # ID unique pour la session principale
        main_session_id = "host_" + generate_random_id(6)
        print("[INFO] - CREATING ROOM for id : " + main_session_id)

        s = sam_hello()
        pub, priv = sam_dest_generate(s)
        sam_create_session(s, main_session_id, priv)
        print(Fore.GREEN + "[SUCESS] Destination generated ! Copy the key and give it to your contact (Dont hesitate to encrypt the DEST)")
        time.sleep(1)
        os.system("cls")
        header = Fore.CYAN + rf"""DEST____________________________________________________________________________________________________________________

{pub}
________________________________________________________________________________________________________________________
    """
        print(header)
        # New SAM CONNEXION saame session ID
        s2 = sam_hello()
        sam_stream_accept(s2, main_session_id)
        print(Fore.CYAN + "[CONNECTED] Start chatting !\n")
        chat_session(s2)
        
    except Exception as e:
        print(f"server error : {e}")

def run_client():
    os.system('cls')
    os.system('title ARGON UNENCRYPTED COMMUNICATION')
    """Workflow to connect to an existing DEST"""
    try:
        print(Fore.CYAN + "Please Enter the DEST in base32 format of your contact.")
        dest_pub = input(">>> ").strip()
        client_session_id = "client_" + generate_random_id(6)
        print("[INFO] - CREATING client id : " + client_session_id)


        # first connexion: session create
        s1 = sam_hello()
        pub, priv = sam_dest_generate(s1)
        sam_create_session(s1, client_session_id, priv)
        
        # 2nd connexion: conect to the SAM stream
        s2 = sam_hello()
        sam_stream_connect(s2, client_session_id, dest_pub)
        print(Fore.CYAN + "[Connected] Start chatting !\n")
        chat_session(s2)
        
    except Exception as e:
        print(f"Client error: {e}")
