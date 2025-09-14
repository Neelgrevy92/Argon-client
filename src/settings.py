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


SETTINGS_FILE = "./settings.ini"
I2P_URL = "http://127.0.0.1:7070/"
REFRESH_INTERVAL = 30 

# --- Helpers ---
def i2p_health():
    stop_refresh = threading.Event()


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
        # get next element or sibling
        next_tag = tag.find_next_sibling()
        if next_tag and hasattr(next_tag, "text"):
            return next_tag.text.strip()
        # or next string
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

    # services status
    services = {}
    table = soup.find("table", {"class":"services"})
    if table:
        for row in table.find_all("tr")[1:]:  # skip header
            cols = row.find_all("td")
            if len(cols) >= 2:
                service = cols[0].text.strip()
                status = cols[1].text.strip()
                services[service] = status
    data["services"] = services

    return data


def colorize_health(data):
    output = []

    def color_line(label, value, good="✅", warn="⚠️", bad="❌", thresholds=None, is_percent=False):
        """Helper pour colorer lignes selon thresholds ou status"""
        if thresholds:
            # convert value to float
            val = float(str(value).replace("%","")) if is_percent else float(value)
            if val >= thresholds[0]:
                color = Fore.GREEN
                emoji = good
            elif val >= thresholds[1]:
                color = Fore.YELLOW
                emoji = warn
            else:
                color = Fore.RED
                emoji = bad
            output.append(Fore.CYAN + f"[{label}] " + color + (f"{val}%" if is_percent else str(val)) + f" {emoji}")
        else:
            # status string
            val = str(value).lower()
            if val in ["ok", "enabled"]:
                color = Fore.GREEN
            elif val in ["firewalled", "warning", "warn"]:
                color = Fore.YELLOW
            else:
                color = Fore.RED
            output.append(Fore.CYAN + f"[{label}] " + color + str(value))

    # Uptime
    color_line("Uptime", data.get("uptime", "N/A"))

    # Network status
    color_line("Network status", data.get("network_status", "N/A"))

    # Tunnel success rate
    color_line("Tunnel success rate", data.get("tunnel_success", 0), thresholds=(70,50), is_percent=True)

    # Received / Sent
    color_line("Received", data.get("received","N/A"))
    color_line("Sent", data.get("sent","N/A"))

    # Transit
    color_line("Transit", data.get("transit","N/A"))

    # Client / Transit tunnels
    ct = data.get("client_tunnels",0)
    tt = data.get("transit_tunnels",0)
    color_line("Client tunnels", ct, thresholds=(1,1))
    color_line("Transit tunnels", tt, thresholds=(1,1))

    # Services
    for service, status in data.get("services", {}).items():
        color_line(service, status)

    return output



def get_i2p_status():
    try:
        response = requests.get(I2P_URL)
        if response.status_code != 200:
            print(Fore.RED + "[ERROR] I2P webconsole unreachable!" + Style.RESET_ALL)
            return None
        soup = BeautifulSoup(response.text, "html.parser")
        return soup
    except Exception as e:
        print(Fore.RED + f"[ERROR] Exception: {e}" + Style.RESET_ALL)
        return None



def load_settings():
    config = configparser.ConfigParser()
    config.read(SETTINGS_FILE)
    return config


def save_settings(config):
    with open(SETTINGS_FILE, "w") as f:
        config.write(f)


def display_settings(config):
    print(Fore.CYAN + "\n--------[CRYPTOGRAPHY & OPSEC]------")
    for k, v in config["CRYPTOGRAPHY & OPSEC"].items():
        print(f"{k} = {v}")

    print(Fore.CYAN + "\n--------[I2P Network]-------------")
    for k, v in config["I2P Network"].items():
        print(f"{k} = {v}")
    print()





def i2p_health():
    stop_refresh = threading.Event()
    
    def refresh_loop():
        response = requests.get("http://127.0.0.1:7070/?page=sam_sessions")
        if response.status_code == "200":
            if "No sessions" in response.content:
                pass 
            else:
                print(Fore.RED + "[CRITICAL] It seems that a SAM session leakage is happening, an instance is running while the client is reponsible for none ==> serious opsec treath !")
                print(Fore.RED + "[CRITICAL] If this is normal continue else go in settings and use the KILL command to kill the router")
                input('...')


        while not stop_refresh.is_set():
            os.system("cls" if os.name=="nt" else "clear")
            soup = get_i2p_status()
            if not soup:
                print(Fore.RED + "[ERROR] Could not fetch I2P status" + Style.RESET_ALL)
                time.sleep(REFRESH_INTERVAL)
                continue
            data = parse_health(soup)
            lines = colorize_health(data)
            print(Fore.CYAN + "---- I2P HEALTH CHECK ----" + Style.RESET_ALL)
            for line in lines:
                print(line)

            print("----TUNNEL INFO-----")
            print('SOON')


            print(Fore.YELLOW + f"\nRefreshing in {REFRESH_INTERVAL}s... Press ENTER to exit." + Style.RESET_ALL)
            for _ in range(REFRESH_INTERVAL):
                if stop_refresh.is_set():
                    break
                time.sleep(1)
    
    # start refresh thread
    t = threading.Thread(target=refresh_loop)
    t.start()
    
    # wait for Enter
    input()
    stop_refresh.set()
    t.join()
    print(Fore.GREEN + "[INFO] Exiting health check..." + Style.RESET_ALL)




def info():
    print(Fore.YELLOW + "[filler] Settings info not implemented yet.")




# --- CLI principal ---
def setting_cli():
    
    os.system('cls' if os.name == 'nt' else 'clear')
    os.system(r'title ARGON CLIENT - SETTINGS' if os.name == 'nt' else "echo -ne '\033]0;ARGON CLIENT - SETTINGS\007'")
    
    header = r"""________________________________________________________________________________________________________________________

Settings  - change any value with [SECTION.KEY] [NEW VALUE]   
Check I2P health with [health]    quit with [q]   [i] settings info
________________________________________________________________________________________________________________________
    """
    print(Fore.CYAN + header)

    ensure_settings_exists()
    config = load_settings()

    while True:
        display_settings(config)
        try:
            choice = input(Fore.CYAN + ">>> " + Style.RESET_ALL).strip()
        except (KeyboardInterrupt, EOFError):
            print(Fore.RED + "\n[!] Interrupted. Returning to main..." + Style.RESET_ALL)
            break

        if choice.lower() in ["q", "quit", "exit"]:
            break
        elif choice.lower() == "health":
            i2p_health()
            os.system("cls" if os.name=="nt" else "clear")
        elif choice.lower() == "i":
            info()
        elif "." in choice:  
            # ex: I2P Network.PERSISTENCE true
            try:
                key, new_val = choice.split(maxsplit=1)
                section, setting = key.split(".", 1)

                if section in config and setting in config[section]:
                    config[section][setting] = new_val
                    save_settings(config)
                    print(Fore.GREEN + f"[✓] {section}.{setting} updated to {new_val}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"[!] {section}.{setting} not found." + Style.RESET_ALL)
            except ValueError:
                print(Fore.YELLOW + "[!] Invalid format. Use: Section.KEY new_value" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "[!] Unknown command." + Style.RESET_ALL)


