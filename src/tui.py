"""
src/tui.py - Modern TUI rendering for Argon Client
Uses rich for panels/tables and InquirerPy for arrow-key navigation
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich import box
from InquirerPy import inquirer
from InquirerPy.separator import Separator
from InquirerPy.utils import get_style
import csv
import os

console = Console()

# ─── Color palette ────────────────────────────────────────────────
ACCENT   = "#00d4aa"   # teal/mint
DIM      = "#555555"
WARN     = "#ffaa00"
ERR      = "#ff4444"
OK       = "#00ff88"
MUTED    = "#888888"
CYAN     = "#00bfff"
PRIV_CLR = "#ff6b9d"   # pink for private keys
PUB_CLR  = "#6bffb8"   # green for public keys

VERSION = "1.0.3"

# ─── InquirerPy style (must be InquirerPyStyle, not raw dict) ────
INQUIRER_STYLE = get_style({
    "questionmark": "#00d4aa bold",
    "answermark": "#00d4aa bold",
    "answer": "#00ff88 bold",
    "input": "#ffffff",
    "question": "#ffffff bold",
    "answered_question": "#888888",
    "instruction": "#555555",
    "long_instruction": "#555555",
    "pointer": "#00d4aa bold",
    "checkbox": "#00d4aa",
    "separator": "#555555",
    "skipped": "#555555",
    "validator": "#ff4444",
    "marker": "#00d4aa",
    "fuzzy_prompt": "#00d4aa",
    "fuzzy_info": "#555555",
    "fuzzy_border": "#00d4aa",
    "fuzzy_match": "#00ff88",
}, style_override=False)


LOGO = r"""[bold #00d4aa]
     ___                            
    /   |  _________ _____  ____    
   / /| | / ___/ __ `/ __ \/ __ \   
  / ___ |/ /  / /_/ / /_/ / / / /  
 /_/  |_/_/   \__, /\____/_/ /_/   
             /____/                
[/]"""

LOGO_SUBTITLE = f"[dim]Anonymous Encrypted Messenger  //  I2P Network  //  v{VERSION}[/dim]"


def render_header():
    """Render the main Argon header with logo"""
    content = Text.from_markup(LOGO + "\n" + LOGO_SUBTITLE)
    panel = Panel(
        Align.center(content),
        border_style=ACCENT,
        box=box.DOUBLE,
        padding=(0, 2),
    )
    console.print(panel)


def render_status_bar(i2pd_running: bool, encryption: bool):
    """Render a compact status bar below the header"""
    i2p_icon = "+" if i2pd_running else "x"
    i2p_color = OK if i2pd_running else ERR
    i2p_status = f"[bold {i2p_color}][{i2p_icon}] I2PD[/]"

    enc_icon = "+" if encryption else "x"
    enc_color = OK if encryption else WARN
    enc_status = f"[bold {enc_color}][{enc_icon}] PGP[/]"

    table = Table(show_header=False, box=None, padding=(0, 3), expand=True)
    table.add_column(justify="center", ratio=1)
    table.add_column(justify="center", ratio=1)
    table.add_column(justify="center", ratio=1)
    table.add_row(i2p_status, enc_status, f"[dim]Network: I2P (SAM 3.3)[/dim]")
    console.print(table)
    console.print()


def main_menu() -> str:
    """Display the main menu with arrow-key selection. Returns the action key."""
    choices = [
        {"name": "  Join Room          Connect to an I2P destination", "value": "join"},
        {"name": "  Create Room        Host a new encrypted room", "value": "create"},
        Separator("--- Management ---"),
        {"name": "  Keychain           Manage PGP keys & aliases", "value": "keychain"},
        {"name": "  Settings           Configure encryption & network", "value": "settings"},
        {"name": "  I2P Health         Monitor router status", "value": "health"},
        Separator("--- Info ---"),
        {"name": "  Guide              How to use Argon", "value": "guide"},
        {"name": "  Quit               Exit Argon Client", "value": "quit"},
    ]

    result = inquirer.select(
        message="",
        choices=choices,
        pointer=">",
        qmark="",
        amark="",
        instruction="(arrows to navigate, Enter to select)",
        style=INQUIRER_STYLE,
        border=True,
    ).execute()

    return result


def key_selection_menu(register_path="./Keychain/register.csv") -> dict:
    """
    Interactive key selection with arrow keys.
    Returns dict with 'private' and 'public' filenames, or None if cancelled.
    """
    private_keys = []
    public_keys = []

    try:
        with open(register_path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['Type'] == 'private':
                    private_keys.append(row)
                elif row['Type'] == 'public':
                    public_keys.append(row)
    except FileNotFoundError:
        render_error("Keychain not found. Generate keys first (Keychain > gen).")
        return None

    if not private_keys or not public_keys:
        render_error("You need at least one private and one public key.")
        return None

    # Render the keychain table
    render_keychain_table(private_keys, public_keys)
    console.print()

    # Select private key
    priv_choices = [
        {"name": f"[{k['ID']}] {k['Alias'] or k['Filename']}", "value": k}
        for k in private_keys
    ]
    priv_choices.append({"name": "<- Back", "value": None})

    selected_priv = inquirer.select(
        message="Select your PRIVATE key (for decryption)",
        choices=priv_choices,
        pointer=">",
        qmark=">>",
        style=INQUIRER_STYLE,
    ).execute()

    if selected_priv is None:
        return None

    # Select public key
    pub_choices = [
        {"name": f"[{k['ID']}] {k['Alias'] or k['Filename']}", "value": k}
        for k in public_keys
    ]
    pub_choices.append({"name": "<- Back", "value": None})

    selected_pub = inquirer.select(
        message="Select recipient's PUBLIC key (for encryption)",
        choices=pub_choices,
        pointer=">",
        qmark=">>",
        style=INQUIRER_STYLE,
    ).execute()

    if selected_pub is None:
        return None

    return {
        "private": selected_priv['Filename'],
        "public": selected_pub['Filename'],
    }


def render_keychain_table(private_keys=None, public_keys=None):
    """Render a rich table of keys"""
    if private_keys is None or public_keys is None:
        private_keys = []
        public_keys = []
        try:
            with open("./Keychain/register.csv", 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row['Type'] == 'private':
                        private_keys.append(row)
                    elif row['Type'] == 'public':
                        public_keys.append(row)
        except FileNotFoundError:
            console.print(f"[{ERR}]No keychain found.[/]")
            return

    table = Table(
        title="Keychain",
        box=box.ROUNDED,
        border_style=ACCENT,
        title_style=f"bold {ACCENT}",
        show_lines=True,
        padding=(0, 1),
    )

    table.add_column("ID", style=f"bold {CYAN}", justify="center", width=6)
    table.add_column("Type", justify="center", width=10)
    table.add_column("Alias", style="bold white", width=15)
    table.add_column("Filename", style=f"dim", max_width=40)

    for k in private_keys:
        alias = k['Alias'] if k['Alias'] else "-"
        table.add_row(
            k['ID'],
            f"[bold {PRIV_CLR}]PRIVATE[/]",
            alias,
            _truncate(k['Filename'], 40),
        )

    for k in public_keys:
        alias = k['Alias'] if k['Alias'] else "-"
        table.add_row(
            k['ID'],
            f"[bold {PUB_CLR}]PUBLIC[/]",
            alias,
            _truncate(k['Filename'], 40),
        )

    console.print(table)


def render_dest_display(dest: str):
    """Render the I2P destination in a copyable panel"""
    panel = Panel(
        f"[bold white]{dest}[/]",
        title=f"[bold {ACCENT}]Your I2P Destination[/]",
        subtitle="[dim]Share this with your contact[/dim]",
        border_style=ACCENT,
        box=box.HEAVY,
        padding=(1, 2),
    )
    console.print(panel)


def render_info_panel(title_text: str, content: str):
    """Render an info panel with given content"""
    panel = Panel(
        content,
        title=f"[bold {CYAN}]{title_text}[/]",
        border_style=CYAN,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)


def render_warning(msg: str):
    """Display a warning message"""
    console.print(f"[bold {WARN}]  [!] {msg}[/]")


def render_error(msg: str):
    """Display an error message"""
    console.print(f"[bold {ERR}]  [x] {msg}[/]")


def render_success(msg: str):
    """Display a success message"""
    console.print(f"[bold {OK}]  [+] {msg}[/]")


def render_info(msg: str):
    """Display an info message"""
    console.print(f"[{MUTED}]  [-] {msg}[/]")


def render_chat_header(encrypted: bool):
    """Render the header for the chat session"""
    enc_label = f"[bold {OK}]End-to-End Encrypted (PGP)[/]" if encrypted else f"[bold {ERR}]UNENCRYPTED[/]"
    panel = Panel(
        Align.center(Text.from_markup(
            f"Chat Session  //  {enc_label}\n"
            f"[dim]Type your message and press Enter  //  Ctrl+C to exit  //  Ctrl+Q actions[/dim]"
        )),
        border_style=ACCENT,
        box=box.ROUNDED,
        padding=(0, 2),
    )
    console.print(panel)


def confirm_action(message: str, default=False) -> bool:
    """Ask a yes/no confirmation"""
    return inquirer.confirm(
        message=message,
        default=default,
        qmark="?",
        style=INQUIRER_STYLE,
    ).execute()


def text_prompt(message: str, qmark=">") -> str:
    """Ask for text input"""
    return inquirer.text(
        message=message,
        qmark=qmark,
        style=INQUIRER_STYLE,
    ).execute()


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string with ellipsis"""
    if len(s) <= max_len:
        return s
    half = (max_len - 3) // 2
    return s[:half] + "..." + s[-half:]


def wait_for_enter(msg="Press Enter to continue..."):
    """Simple enter prompt styled"""
    console.print(f"\n[dim]{msg}[/dim]", end="")
    input()
