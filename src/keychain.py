from colorama import Fore, Style, init
import os
import csv
from .encrypt import * 
import re 


init(autoreset=True)

REGISTER_FILE = "./Keychain/register.csv"
PRIVATE_DIR = "./Keychain/private"
PUBLIC_DIR = "./Keychain/public"


def verify_register_integrity():
    """
    Verify that register.csv entries point to real files.
    Remove orphan entries automatically.
    """
    ensure_register_exists()
    entries = load_register()
    cleaned_entries = []
    removed = []

    for e in entries:
        path = os.path.join(PRIVATE_DIR if e["Type"] == "private" else PUBLIC_DIR, e["Filename"])
        if os.path.exists(path):
            cleaned_entries.append(e)
        else:
            removed.append(e)

    if removed:
        for e in removed:
            print(Fore.RED + f" - ID {e['ID']} ({e['Type']}) -> missing file {e['Filename']}" + Style.RESET_ALL)
        save_register(cleaned_entries)

    return cleaned_entries


def ensure_register_exists():
    """Create register.csv if missing."""
    if not os.path.exists(REGISTER_FILE):
        with open(REGISTER_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Type", "Filename", "Alias"])


def load_register():
    """Load register.csv as list of dicts."""
    with open(REGISTER_FILE, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def save_register(entries):
    """Save entries to register.csv."""
    with open(REGISTER_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ID", "Type", "Filename", "Alias"])
        writer.writeheader()
        writer.writerows(entries)


def next_id(entries, key_type):
    """Generate next available ID for private/public keys."""
    prefix = 1000 if key_type == "private" else 2000
    existing_ids = [int(e["ID"]) for e in entries if e["Type"] == key_type]
    return prefix + 1 if not existing_ids else max(existing_ids) + 1


def clean_filename(filename, max_len=30):
    """
    Supprime le préfixe e_<timestamp>Z_ si présent.
    Tronque aussi si trop long pour l'affichage.
    """
    # remove  e_20250926T135300Z_ (the ones that the CLI generate)
    cleaned = re.sub(r"^e_\d{8}T\d{6}Z_", "", filename)

    # if still too long or from other GPG sources
    if len(cleaned) > max_len:
        half = (max_len - 3) // 2
        cleaned = cleaned[:half] + "..." + cleaned[-half:]

    return cleaned

def sync_keys_with_files():
    """Ensure register.csv includes all files present in Keychain folders."""
    entries = load_register()

    # PRIVATE -> only .bin
    for file in os.listdir(PRIVATE_DIR):
        if file.endswith(".bin") and not any(e["Filename"] == file for e in entries):
            new_id = next_id(entries, "private")
            entries.append({"ID": str(new_id), "Type": "private", "Filename": file, "Alias": ""})

    # PUBLIC -> only .asc
    for file in os.listdir(PUBLIC_DIR):
        if file.endswith(".asc") and not any(e["Filename"] == file for e in entries):
            new_id = next_id(entries, "public")
            entries.append({"ID": str(new_id), "Type": "public", "Filename": file, "Alias": ""})

    save_register(entries)


def delete_key(entries, key_id, remove_file=True):
    """Delete a key from register, optionally remove the file too."""
    for e in entries:
        if e["ID"] == key_id:
            if remove_file:
                path = os.path.join(PRIVATE_DIR if e["Type"] == "private" else PUBLIC_DIR, e["Filename"])
                if os.path.exists(path):
                    os.remove(path)
            entries.remove(e)
            save_register(entries)
            print(Fore.RED + f"[✓] Key {key_id} deleted." + Style.RESET_ALL)
            return
    print(Fore.YELLOW + f"[!] ID {key_id} not found." + Style.RESET_ALL)


def bind_alias(entries, key_id, alias):
    """Bind an alias to a key (1 public + 1 private max per alias)."""
    for e in entries:
        if e["ID"] == key_id:
            # Prevent alias conflicts
            same_alias = [x for x in entries if x["Alias"] == alias]
            if any(x["Type"] == e["Type"] for x in same_alias):
                print(Fore.YELLOW + f"[!] Alias '{alias}' already bound to a {e['Type']} key." + Style.RESET_ALL)
                return
            e["Alias"] = alias
            save_register(entries)
            print(Fore.GREEN + f"[✓] Key {key_id} bound to alias '{alias}'." + Style.RESET_ALL)
            return
    print(Fore.YELLOW + f"[!] ID {key_id} not found." + Style.RESET_ALL)



def print_table(entries):
    """Pretty print private and public keys side by side."""
    private_keys = [e for e in entries if e["Type"] == "private"]
    public_keys = [e for e in entries if e["Type"] == "public"]

    print(Fore.CYAN + "PRIVATE KEYS".ljust(60) + " | " + "PUBLIC KEYS")
    print(Fore.CYAN + "-" * 120)

    max_len = max(len(private_keys), len(public_keys))
    for i in range(max_len):
        left = ""
        right = ""

        if i < len(private_keys):
            e = private_keys[i]
            alias = e["Alias"] if e["Alias"] else Fore.YELLOW + "(no alias)"
            filename = clean_filename(e["Filename"])
            left = f"[{e['ID']}] {alias} - {filename}"

        if i < len(public_keys):
            e = public_keys[i]
            alias = e["Alias"] if e["Alias"] else "(no alias)"
            filename = clean_filename(e["Filename"])
            right = f"[{e['ID']}] {alias} - {filename}"

        print(left.ljust(60) + " | " + right)

    print(Fore.CYAN + "-" * 120)

def cli_keychain():
    """Main interactive loop for keychain management."""
    ensure_register_exists()
    sync_keys_with_files()

    try:
        while True:
            os.system("cls" if os.name == "nt" else "clear")

            # Header & commands menu
            header = r"""________________________________________________________________________________________________________________________

Argon Client Keychain - Manage your PGP keys |  If you use main alias it will be used by default 
________________________________________________________________________________________________________________________
            """
            print(Fore.CYAN + header)
            print("[i] - All the private keys are safely encrypted.")
            print("gen : generate a new keypair")
            print("d [ID]: delete a key with its ID (remove file + csv)")
            print("r [ID]: remove a key with its ID (only from csv, keep file)")
            print("b [ID] [NAME]: bind the key to a specific name (max 1 pub + 1 priv per alias)")
            print("q: quit keychain and return to main menu\n")

            # Refresh register and cleanup
            entries = verify_register_integrity()
            print_table(entries)

            # Read user command
            cmd = input(Fore.CYAN + ">>> " + Style.RESET_ALL).strip().split()
            if not cmd:
                continue

            if cmd[0] in ["exit", "quit", "q"]:
                print(Fore.GREEN + "[INFO] Returning to main menu..." + Style.RESET_ALL)
                break

            elif cmd[0] == "gen":
                try:
                    choice = input("Enter <Name> <Email>: ").strip()
                    name, mail = choice.split()

                    # Generate keypair
                    priv_obj, pub_obj, priv_path, pub_path = generate_keypair(name, mail)

                    # Protect private key with Argon2
                    priv_filename_bin = os.path.splitext(os.path.basename(priv_path))[0] + ".bin"
                    dest_file = os.path.join(PRIVATE_DIR, priv_filename_bin)
                    argon_protect(priv_path, dest_file)
                    os.remove(priv_path)

                    # Update register
                    entries = load_register()
                    new_priv_id = next_id(entries, "private")
                    new_pub_id = next_id(entries, "public")
                    pub_filename = os.path.basename(pub_path)

                    entries.append({"ID": str(new_priv_id), "Type": "private", "Filename": priv_filename_bin, "Alias": ""})
                    entries.append({"ID": str(new_pub_id), "Type": "public", "Filename": pub_filename, "Alias": ""})
                    save_register(entries)

                    print(Fore.GREEN + f"[SUCCESS] Keypair registered: private ID {new_priv_id}, public ID {new_pub_id}" + Style.RESET_ALL)
                    input("Press Enter to continue...")

                except ValueError:
                    print(Fore.YELLOW + "Please enter: <Name> <email> (separated by space)." + Style.RESET_ALL)
                    input("Press Enter to continue...")
                except Exception as e:
                    print(Fore.RED + f"[ERROR] key generation failed: {e}" + Style.RESET_ALL)
                    input("Press Enter to continue...")

            elif cmd[0] == "d" and len(cmd) == 2:
                delete_key(entries, cmd[1], remove_file=True)

            elif cmd[0] == "r" and len(cmd) == 2:
                delete_key(entries, cmd[1], remove_file=False)

            elif cmd[0] == "b" and len(cmd) >= 3:
                bind_alias(entries, cmd[1], " ".join(cmd[2:]))

            else:
                print(Fore.YELLOW + "[!] Unknown command." + Style.RESET_ALL)
                input("Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n" + Fore.GREEN + "[INFO] CTRL+C detected, returning to main menu..." + Style.RESET_ALL)
        return
