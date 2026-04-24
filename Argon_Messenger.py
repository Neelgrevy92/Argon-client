"""
Argon Messenger - Anonymous Encrypted Messenger over I2P
Main entry point with modern TUI interface
"""
import os
import subprocess
import time
import shutil
import sys

from src.tui import (
    console, render_header, render_status_bar, main_menu,
    key_selection_menu, render_warning, render_error,
    render_success, render_info, render_chat_header,
    confirm_action, text_prompt, wait_for_enter,
    render_info_panel, render_dest_display,
)
from src.keychain import cli_keychain
from src.settings import setting_cli, i2p_health, ensure_settings_exists
from src.guide import guide
from src.ecchat import join_room, create_room
from src.unsafe.chat import run_server, run_client
from src.installer import check_files
from src.helpers import (
    is_i2p_encryption_enabled, argon_protect, find_keys_by_alias,
    clear_screen, set_terminal_title,
)


SETTINGS_FILE = "./settings.ini"


def boot_sequence():
    """
    Startup: check i2pd installation, start router, handle misplaced keys.
    Returns True if boot was successful.
    """
    set_terminal_title("Argon · Booting...")
    clear_screen()

    console.print()
    render_header()
    console.print()

    # ── Check i2pd installation ──────────────────────────────────
    with console.status("[bold #00d4aa]Checking i2pd installation...", spinner="dots"):
        time.sleep(0.5)
        installed = check_files()

    if not installed:
        render_error("i2pd is required but not installed. The application cannot continue.")
        render_error("Please install i2pd manually and restart.")
        wait_for_enter("Press Enter to exit...")
        sys.exit(1)

    render_success("All dependencies ready")

    # ── Check if i2pd is running ─────────────────────────────────
    import psutil
    i2pd_running = False
    for proc in psutil.process_iter(['name']):
        try:
            if 'i2pd' in proc.info['name'].lower():
                i2pd_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if i2pd_running:
        render_info("I2P router already running, SAM service available")
        render_warning("We recommend resetting the router after each use (fingerprinting risk)")
    else:
        render_info("Starting a new I2P router...")
        if os.name == 'nt':
            subprocess.Popen(['.\\i2pd.exe'])
        else:
            subprocess.Popen(['i2pd'])
        time.sleep(1)
        render_success("I2P router started")

    # ── Handle misplaced keys ────────────────────────────────────
    KEY_EXTENSIONS = ['.asc', '.gpg', '.bin', '.key']
    root = os.getcwd()

    for file in os.listdir(root):
        filepath = os.path.join(root, file)
        if os.path.isfile(filepath) and any(file.lower().endswith(ext) for ext in KEY_EXTENSIONS):
            if file.lower().endswith('.asc'):
                if 'public' in file.lower():
                    render_warning(f"Misplaced PUBKEY: {file} → moving to ./Keychain/public")
                    dest = os.path.join('./Keychain/public', file)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.move(filepath, dest)
                elif 'secret' in file.lower() or 'private' in file.lower():
                    render_error(f"Misplaced PRIVATE KEY (high risk): {file}")
                    time.sleep(1)
                    render_info("Encrypting and moving to secure storage...")
                    dest_file = os.path.join("./Keychain/private", file + ".bin")
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    argon_protect(filepath, dest_file)
                    os.remove(filepath)
                    render_info("Bind your private key to an alias in the Keychain manager")
            elif file.lower().endswith('.bin'):
                render_warning(f"Misplaced encrypted key: {file} → moving to ./Keychain/private")
                dest = os.path.join('./Keychain/private', file)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.move(filepath, dest)

    ensure_settings_exists()
    time.sleep(0.5)
    return True


def handle_join_room():
    """Handle the Join Room flow with TUI key selection"""
    clear_screen()
    set_terminal_title("Argon · Join Room")

    if not is_i2p_encryption_enabled():
        render_warning("PGP encryption is DISABLED in settings")
        render_warning("NO ENCRYPTION will be used in this conversation")
        if confirm_action("Continue without encryption?"):
            run_client()
            return
        else:
            return

    render_info_panel(
        "Join Encrypted Room",
        "[bold]Select your keys for this conversation[/]\n\n"
        "[dim]• Your PRIVATE key is used to decrypt incoming messages\n"
        "• The recipient's PUBLIC key is used to encrypt outgoing messages\n"
        "• Press Enter on empty selection to use default 'main' keypair[/]"
    )
    console.print()

    # Try default keys first
    use_default = confirm_action("Use default keypair (alias 'main')?", default=True)

    if use_default:
        main_keys = find_keys_by_alias('main')
        if main_keys['private'] and main_keys['public']:
            keychain_dir = 'Keychain'
            private_dir = os.path.join(keychain_dir, 'private')
            public_dir = os.path.join(keychain_dir, 'public')
            privkey_path = os.path.join(private_dir, main_keys['private'])
            pubkey_path = os.path.join(public_dir, main_keys['public'])

            if os.path.exists(privkey_path) and os.path.exists(pubkey_path):
                render_success(f"Using private key: {main_keys['private']}")
                render_success(f"Using public key: {main_keys['public']}")
                join_room(main_keys['public'], main_keys['private'])
                return

        render_error("No keypair with alias 'main' found. Select manually.")

    # Manual key selection
    keys = key_selection_menu()
    if keys is None:
        return

    render_success(f"Private: {keys['private']}")
    render_success(f"Public: {keys['public']}")
    join_room(keys['public'], keys['private'])


def handle_create_room():
    """Handle the Create Room flow with TUI key selection"""
    clear_screen()
    set_terminal_title("Argon · Create Room")

    if not is_i2p_encryption_enabled():
        render_warning("PGP encryption is DISABLED in settings")
        render_warning("NO ENCRYPTION will be used in this conversation")
        if confirm_action("Continue without encryption?"):
            run_server()
            return
        else:
            return

    render_info_panel(
        "Create Encrypted Room",
        "[bold]Select your keys for hosting[/]\n\n"
        "[dim]• Your PRIVATE key is used to decrypt incoming messages\n"
        "• The recipient's PUBLIC key is used to encrypt outgoing messages\n"
        "• You will receive an I2P destination to share with your contact[/]"
    )
    console.print()

    use_default = confirm_action("Use default keypair (alias 'main')?", default=True)

    if use_default:
        main_keys = find_keys_by_alias('main')
        if main_keys['private'] and main_keys['public']:
            keychain_dir = 'Keychain'
            private_dir = os.path.join(keychain_dir, 'private')
            public_dir = os.path.join(keychain_dir, 'public')
            privkey_path = os.path.join(private_dir, main_keys['private'])
            pubkey_path = os.path.join(public_dir, main_keys['public'])

            if os.path.exists(privkey_path) and os.path.exists(pubkey_path):
                render_success(f"Using private key: {main_keys['private']}")
                render_success(f"Using public key: {main_keys['public']}")
                create_room(main_keys['private'], main_keys['public'])
                return

        render_error("No keypair with alias 'main' found. Select manually.")

    keys = key_selection_menu()
    if keys is None:
        return

    render_success(f"Private: {keys['private']}")
    render_success(f"Public: {keys['public']}")
    create_room(keys['private'], keys['public'])


def main():
    """Main entry point for the Argon I2P Message Service"""
    boot_sequence()

    while True:
        set_terminal_title("Argon · Main Menu")
        clear_screen()

        # Detect current state for status bar
        import psutil
        i2pd_running = any(
            'i2pd' in (p.info.get('name') or '').lower()
            for p in psutil.process_iter(['name'])
        )
        encryption = is_i2p_encryption_enabled()

        render_header()
        render_status_bar(i2pd_running, encryption)

        try:
            choice = main_menu()
        except KeyboardInterrupt:
            render_info("Goodbye!")
            sys.exit(0)

        if choice == "join":
            handle_join_room()
            wait_for_enter()

        elif choice == "create":
            handle_create_room()
            wait_for_enter()

        elif choice == "keychain":
            cli_keychain()

        elif choice == "settings":
            setting_cli()

        elif choice == "health":
            i2p_health()

        elif choice == "guide":
            guide()

        elif choice == "quit":
            render_info("Shutting down Argon Client...")
            time.sleep(0.3)
            sys.exit(0)


main()