from colorama import Fore, Back, Style
from colorama import init
init(autoreset=True)
import os 
import csv


REGISTER_FILE = "./Keychain/register.csv"
PRIVATE_DIR = "./Keychain/private"
PUBLIC_DIR = "./Keychain/public"





def ensure_register_exists():
    if not os.path.exists(REGISTER_FILE):
        with open(REGISTER_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Type", "Filename", "Alias"])


def load_register():
    with open(REGISTER_FILE, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def save_register(entries):
    with open(REGISTER_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ID", "Type", "Filename", "Alias"])
        writer.writeheader()
        writer.writerows(entries)


def next_id(entries, key_type):
    prefix = 1000 if key_type == "private" else 2000
    existing_ids = [int(e["ID"]) for e in entries if e["Type"] == key_type]
    return prefix + 1 if not existing_ids else max(existing_ids) + 1


def sync_keys_with_files():
    entries = load_register()

    # PRIVATE -> only .bin
    for file in os.listdir(PRIVATE_DIR):
        if file.endswith(".bin") and not any(e["Filename"] == file for e in entries):
            new_id = next_id(entries, "private")
            entries.append({"ID": str(new_id), "Type": "private", "Filename": file, "Alias": ""})

    # PUBLIC -> only .asc no argon2
    for file in os.listdir(PUBLIC_DIR):
        if file.endswith(".asc") and not any(e["Filename"] == file for e in entries):
            new_id = next_id(entries, "public")
            entries.append({"ID": str(new_id), "Type": "public", "Filename": file, "Alias": ""})

    save_register(entries)


def delete_key(entries, key_id, remove_file=True):
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
    for e in entries:
        if e["ID"] == key_id:
            # verification : no alias has more than 1 PRIV and PUB key
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
    private_keys = [e for e in entries if e["Type"] == "private"]
    public_keys = [e for e in entries if e["Type"] == "public"]

    print(Fore.CYAN +"PRIVATE KEYS".ljust(60) + " | " + Fore.CYAN +"PUBLIC KEYS")
    print(Fore.CYAN +"-" * 120)

    max_len = max(len(private_keys), len(public_keys))
    for i in range(max_len):
        left = ""
        right = ""

        if i < len(private_keys):
            e = private_keys[i]
            alias = e["Alias"] if e["Alias"] else Fore.YELLOW + "(no alias)"
            left = f"[{e['ID']}] {alias} - {e['Filename']}"

        if i < len(public_keys):
            e = public_keys[i]
            alias = e["Alias"] if e["Alias"] else "(no alias)"
            right = f"[{e['ID']}] {alias} - {e['Filename']}"

        print(left.ljust(60) + " | " + right)

    print(Fore.CYAN +"-" * 120)

def cli_keychain():
    os.system(r'cls')
    header = r"""________________________________________________________________________________________________________________________

Argon Client Keychain - Manage your PGP keys | /!\ choose safe aliases only, if you use main alias it will be used by default
________________________________________________________________________________________________________________________
    """
    print(Fore.CYAN + header)
    print("[i] - All the private keys are safely encrypted.")
    print("d [ID]: delete a key with its ID (remove file + csv)")
    print("r [ID]: remove a key with its ID (only from csv, keep file)")
    print("b [ID] [NAME]: bind the key to a specific name /!\\ one public + one private max per NAME")
    print("q: quit keychain and return to main menu")
    print()

    ensure_register_exists()
    sync_keys_with_files()
    entries = load_register()

    try:
        while True:
            print_table(entries)
            cmd = input(Fore.CYAN + ">>> " + Style.RESET_ALL).strip().split()

            if not cmd:
                continue
            if cmd[0] in ["exit", "quit", "q"]:
                print(Fore.GREEN + "[INFO] Returning to main menu..." + Style.RESET_ALL)
                break
            elif cmd[0] == "d" and len(cmd) == 2:
                delete_key(entries, cmd[1], remove_file=True)
                entries = load_register()
            elif cmd[0] == "r" and len(cmd) == 2:
                delete_key(entries, cmd[1], remove_file=False)
                entries = load_register()
            elif cmd[0] == "b" and len(cmd) >= 3:
                bind_alias(entries, cmd[1], " ".join(cmd[2:]))
                entries = load_register()
            else:
                print(Fore.YELLOW + "[!] Unknown command." + Style.RESET_ALL)

    except KeyboardInterrupt:
        print("\n" + Fore.GREEN + "[INFO] CTRL+C detected, returning to main menu..." + Style.RESET_ALL)
        return


    
