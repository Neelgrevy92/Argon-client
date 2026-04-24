"""
src/settings.py - Settings management and I2P health monitoring
"""
from colorama import Fore, Style, init
init(autoreset=True)
import os
import configparser
import signal
import sys
import requests
from bs4 import BeautifulSoup
import time
import threading
from .helpers import clear_screen, set_terminal_title


SETTINGS_FILE = "./settings.ini"
I2P_URL = "http://127.0.0.1:7070/"
REFRESH_INTERVAL = 30


def ensure_settings_exists():
    """Créer un settings.ini par défaut si inexistant"""
    if not os.path.exists(SETTINGS_FILE):
        config = configparser.ConfigParser()
        config["CRYPTOGRAPHY & OPSEC"] = {
            "DISABLE_ARGON2": "false"
        }
        config["I2P Network"] = {
            "PERSISTENCE": "false",
            "RANDOM_I2P_ID": "true",
            "ENCRYPT_I2P_COMM": "true"
        }
        with open(SETTINGS_FILE, "w") as f:
            config.write(f)


def parse_health(soup):
    data = {}

    def get_text_after(label):
        tag = soup.find(text=label)
        if not tag:
            return "N/A"
        next_tag = tag.find_next_sibling()
        if next_tag and hasattr(next_tag, "text"):
            return next_tag.text.strip()
        next_string = tag.find_next(string=True)
        if next_string:
            return next_string.strip()
        return "N/A"

    data["uptime"] = get_text_after("Uptime:")
    data["network_status"] = get_text_after("Network status:")

    ts_val = get_text_after("Tunnel creation success rate:")
    try:
        data["tunnel_success"] = float(ts_val.replace("%", ""))
    except:
        data["tunnel_success"] = 0.0

    data["received"] = get_text_after("Received:")
    data["sent"] = get_text_after("Sent:")
    data["transit"] = get_text_after("Transit:")

    ct_val = get_text_after("Client Tunnels:")
    tt_val = get_text_after("Transit Tunnels:")
    try:
        data["client_tunnels"] = int(ct_val)
    except:
        data["client_tunnels"] = 0
    try:
        data["transit_tunnels"] = int(tt_val)
    except:
        data["transit_tunnels"] = 0

    services = {}
    table = soup.find("table", {"class":"services"})
    if table:
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 2:
                service = cols[0].text.strip()
                status = cols[1].text.strip()
                services[service] = status
    data["services"] = services

    return data


def get_i2p_status():
    try:
        response = requests.get(I2P_URL)
        if response.status_code != 200:
            return None
        soup = BeautifulSoup(response.text, "html.parser")
        return soup
    except Exception:
        return None


def load_settings():
    config = configparser.ConfigParser()
    config.read(SETTINGS_FILE)
    return config


def save_settings(config):
    with open(SETTINGS_FILE, "w") as f:
        config.write(f)


def render_health_rich(data):
    """Render health data using rich tables"""
    from .tui import console, ACCENT, OK, WARN, ERR, CYAN
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    table = Table(
        title="I2P Router Health",
        box=box.ROUNDED,
        border_style=ACCENT,
        title_style=f"bold {ACCENT}",
        show_lines=True,
    )
    table.add_column("Metric", style=f"bold {CYAN}", width=25)
    table.add_column("Value", width=20)
    table.add_column("Status", justify="center", width=8)

    # Uptime
    table.add_row("Uptime", str(data.get("uptime", "N/A")), "--")

    # Network status
    ns = str(data.get("network_status", "N/A"))
    ns_color = OK if ns.lower() == "ok" else WARN if "firewall" in ns.lower() else ERR
    table.add_row("Network Status", f"[{ns_color}]{ns}[/]", "--")

    # Tunnel success
    ts = data.get("tunnel_success", 0)
    ts_color = OK if ts >= 70 else WARN if ts >= 50 else ERR
    ts_icon = "[+]" if ts >= 70 else "[!]" if ts >= 50 else "[x]"
    table.add_row("Tunnel Success", f"[{ts_color}]{ts}%[/]", ts_icon)

    # Bandwidth
    table.add_row("Received", str(data.get("received", "N/A")), "<<")
    table.add_row("Sent", str(data.get("sent", "N/A")), ">>")
    table.add_row("Transit", str(data.get("transit", "N/A")), "<>")

    # Tunnels
    ct = data.get("client_tunnels", 0)
    tt = data.get("transit_tunnels", 0)
    ct_color = OK if ct >= 1 else ERR
    tt_color = OK if tt >= 1 else ERR
    table.add_row("Client Tunnels", f"[{ct_color}]{ct}[/]", "--")
    table.add_row("Transit Tunnels", f"[{tt_color}]{tt}[/]", "--")

    # Services
    for service, status in data.get("services", {}).items():
        s_color = OK if status.lower() in ["ok", "enabled"] else WARN
        table.add_row(service, f"[{s_color}]{status}[/]", "--")

    console.print(table)


def i2p_health():
    """Monitor I2P health with rich rendering"""
    from .tui import console, render_info, render_error, render_warning

    stop_refresh = threading.Event()

    def refresh_loop():
        try:
            response = requests.get("http://127.0.0.1:7070/?page=sam_sessions", timeout=5)
            if response.status_code == 200:
                if "No sessions" not in str(response.content):
                    render_warning("SAM session leakage detected! An unknown instance is running.")
                    render_warning("If unexpected, kill the router from settings.")
                    input('...')
        except:
            pass

        while not stop_refresh.is_set():
            clear_screen()
            soup = get_i2p_status()
            if not soup:
                render_error("Could not fetch I2P status")
                time.sleep(REFRESH_INTERVAL)
                continue
            data = parse_health(soup)
            render_health_rich(data)

            console.print(f"\n[dim]Refreshing in {REFRESH_INTERVAL}s... Press ENTER to exit.[/dim]")
            for _ in range(REFRESH_INTERVAL):
                if stop_refresh.is_set():
                    break
                time.sleep(1)

    t = threading.Thread(target=refresh_loop)
    t.start()

    input()
    stop_refresh.set()
    t.join()
    render_info("Exiting health check...")


def render_settings_rich(config):
    """Render settings as a rich table"""
    from .tui import console, ACCENT, CYAN, OK, WARN
    from rich.table import Table
    from rich import box

    table = Table(
        title="Configuration",
        box=box.ROUNDED,
        border_style=ACCENT,
        title_style=f"bold {ACCENT}",
        show_lines=True,
    )
    table.add_column("Section", style=f"bold {CYAN}", width=25)
    table.add_column("Key", style="bold white", width=25)
    table.add_column("Value", width=15, justify="center")

    for section in config.sections():
        for key, value in config[section].items():
            val_color = OK if value.lower() == "true" else WARN if value.lower() == "false" else "white"
            table.add_row(section, key.upper(), f"[{val_color}]{value}[/]")

    console.print(table)


def setting_cli():
    """Settings CLI with TUI"""
    from .tui import (
        console, render_info_panel, render_success, render_error,
        render_warning, render_info, wait_for_enter, ACCENT, INQUIRER_STYLE
    )
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator

    clear_screen()
    set_terminal_title('Argon · Settings')

    ensure_settings_exists()
    config = load_settings()

    while True:
        clear_screen()
        console.print()
        render_info_panel(
            "Settings",
            "[bold]Configure Argon Client[/]\n\n"
            "[dim]Modify values to customize encryption, network, and security behavior[/dim]"
        )
        console.print()

        render_settings_rich(config)
        console.print()

        choices = [
            {"name": "  Toggle a setting", "value": "toggle"},
            {"name": "  I2P Health Monitor", "value": "health"},
            Separator(),
            {"name": "  <- Back to main menu", "value": "quit"},
        ]

        action = inquirer.select(
            message="",
            choices=choices,
            pointer=">",
            qmark="",
            amark="",
            instruction="(arrows to navigate, Enter to select)",
            style=INQUIRER_STYLE,
        ).execute()

        if action == "quit":
            break

        elif action == "health":
            i2p_health()

        elif action == "toggle":
            # Build list of all settings as selectable choices
            setting_choices = []
            for section in config.sections():
                for key, value in config[section].items():
                    setting_choices.append({
                        "name": f"{section} → {key.upper()} = {value}",
                        "value": (section, key, value),
                    })
            setting_choices.append({"name": "<- Cancel", "value": None})

            selected = inquirer.select(
                message="Select setting to modify",
                choices=setting_choices,
                pointer=">",
                qmark=">",
                style=INQUIRER_STYLE,
            ).execute()

            if selected is None:
                continue

            section, key, current_val = selected

            # For boolean values, toggle. Otherwise ask for input.
            if current_val.lower() in ["true", "false"]:
                new_val = "false" if current_val.lower() == "true" else "true"
                config[section][key] = new_val
                save_settings(config)
                render_success(f"{section}.{key.upper()} → {new_val}")
            else:
                from .tui import text_prompt
                new_val = text_prompt(f"New value for {key.upper()}", qmark=">")
                config[section][key] = new_val
                save_settings(config)
                render_success(f"{section}.{key.upper()} → {new_val}")

            wait_for_enter()
