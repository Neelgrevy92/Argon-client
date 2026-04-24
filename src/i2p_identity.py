import os
from pgpy import PGPMessage
from .ecchat import sam_hello, sam_dest_generate
from .tui import render_info, render_success, render_warning, render_error, WARN

def get_or_create_static_i2p_dest(private_key_obj, public_key_obj, alias: str):
    """
    Looks for the encrypted static I2P destination on disk.
    If it exists, decrypts and returns (pub, priv).
    If not, requests a new one from SAM, encrypts it with the PGP public key,
    saves it to disk, and returns (pub, priv).
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_dest_path = os.path.join(base_dir, "storage", "DEST", "contacts", f"{alias}_i2p_static.pgp")

    if os.path.exists(static_dest_path):
        render_info(f"Loading existing static identity for alias '{alias}'...")
        try:
            with open(static_dest_path, "r") as f:
                encrypted_data = f.read()
            
            encrypted_msg = PGPMessage.from_blob(encrypted_data)
            decrypted = private_key_obj.decrypt(encrypted_msg)
            
            # The decrypted message format: "PUB=... PRIV=..."
            if isinstance(decrypted.message, (bytes, bytearray)):
                decrypted_str = decrypted.message.decode('utf-8', errors='ignore')
            else:
                decrypted_str = str(decrypted.message)
            
            # PGP might wrap long lines by inserting \n or \r. We must remove them!
            decrypted_str = decrypted_str.replace('\n', '').replace('\r', '').strip()
            
            # The format is strictly "PUB=... PRIV=..."
            # We can split by " PRIV=" to safely get both parts
            pub_part, priv_part = decrypted_str.split(" PRIV=")
            pub = pub_part.replace("PUB=", "").strip()
            priv = priv_part.strip()
            
            # Debug (remove in prod)
            # print(f"[DEBUG] Loaded PRIV length: {len(priv)} characters")
            
            render_success("Static I2P identity loaded successfully.")
            print(f"[{WARN}!] Static identity reduces anonymity.\n[{WARN}!] Use only for trusted contacts.\n")
            return pub, priv
        except Exception as e:
            render_error(f"Failed to decrypt static identity: {e}")
            render_warning("Will generate a new one.")
            # Fallthrough to generate new

    render_info("Generating new static I2P identity...")
    s = sam_hello()
    pub, priv = sam_dest_generate(s)
    
    # Encrypt "PUB=... PRIV=..." with our own public key
    payload = f"PUB={pub} PRIV={priv}"
    message = PGPMessage.new(payload)
    
    # We encrypt using our public key. So only our private key can decrypt it later.
    encrypted = public_key_obj.encrypt(message)
    
    with open(static_dest_path, "w") as f:
        f.write(str(encrypted))
        
    render_success(f"New static I2P identity generated and saved to {static_dest_path}")
    print(f"[{WARN}!] Static identity reduces anonymity.\n[{WARN}!] Use only for trusted contacts.\n")
    
    return pub, priv
