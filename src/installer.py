import platform
import os
import sys
import requests
from bs4 import BeautifulSoup
import re
import zipfile
import io
import time
from colorama import Fore, Style, init
init(autoreset=True)

def install_from_github(architecture):
    """
    Download + install the correct I2P version from github
    """
    print(f"[INFO] - Searching for i2pd Windows x{architecture} version...")
    
    
    api_url = "https://api.github.com/repos/PurpleI2P/i2pd/releases/latest"
    
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Argon-Messenger-Installer/1.0'
    }
    
    try:
        # get info
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        release_data = response.json()
        version = release_data['tag_name'].lstrip('v')
        print(f"[INFO] - Latest version found: {version}")
        
        # search correct x asset
        windows_asset = None
        for asset in release_data['assets']:
            asset_name = asset['name'].lower()
            
            #is it .exe ?
            is_windows = ('.exe' in asset_name or 
                         'windows' in asset_name or 
                         'win' in asset_name)
            
            # is it the correct arch
            is_correct_arch = False
            if architecture == "64":
                is_correct_arch = any(x in asset_name for x in ['x64', '64', 'amd64', 'win64'])
            else:  # 32-bit
                is_correct_arch = any(x in asset_name for x in ['x86', '32', 'win32', 'i686'])
            
            if is_windows and is_correct_arch:
                windows_asset = asset
                break
        
        if not windows_asset:
            print(Fore.RED + "[ERROR] - No matching Windows executable found for your architecture")
            show_manual_instructions(architecture, version)
            input("Press Enter to continue...")
            return False
        
        print(f"[INFO] - Found matching file: {windows_asset['name']}")
        print(f"[INFO] - Downloading... (this may take a moment)")
        
        # Download files
        download_url = windows_asset['browser_download_url']
        download_response = requests.get(download_url, stream=True, timeout=60)
        download_response.raise_for_status()
        
        # Where to download ?
        download_path = os.path.join("..", windows_asset['name'])
        
        # Progression bar 
        total_size = int(download_response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(download_path, 'wb') as f:
            for chunk in download_response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        print(Fore.CYAN + f"\rDownload progress: {progress:.1f}%", end='')
        
        print(Fore.GREEN + f"\n[SUCCESS] - Downloaded: {download_path}")
        
        # if its a zip --> extract 
        if download_path.endswith('.zip'):
            print("[INFO] - Extracting ZIP file...")
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall("..")
            print("[INFO] - Extraction completed")
            
            # delete the zip
            os.remove(download_path)
            print("[INFO] - Cleaned up ZIP file")
        
        print(Fore.GREEN + "[SUCCESS] - i2pd installed successfully!")
        print("[INFO] - Please restart the application")
        return True
        
    except requests.RequestException as e:
        print(Fore.RED + f"[ERROR] - Network error: {e}")
        show_manual_instructions(architecture, "latest")
        input("Press Enter to continue...")
        return False
    except Exception as e:
        print(Fore.RED + f"[ERROR] - Installation failed: {e}")
        show_manual_instructions(architecture, "latest")
        input("Press Enter to continue...")
        return False

def show_manual_instructions(architecture, version):
    """
    Affiche les instructions d'installation manuelle
    """
    tuto = f"""
    HOW TO INSTALL MANUALLY :

    - Go to https://github.com/PurpleI2P/i2pd/releases and download the latest release
    - Look for the Windows x{architecture} version (usually named like 'i2pd-{version}-win{architecture}.exe' or similar)
    - Download the file and place it in the same directory as The Argon.exe executable
    - Restart the application
    - Enjoy anonymous encrypted chatting!
    
    Direct download link might be:
    https://github.com/PurpleI2P/i2pd/releases/download/{version}/i2pd-{version}-win{architecture}.exe
    """
    
    print(Fore.YELLOW + tuto)

def check_router(root_dir="."):
    """
    is the router here ?
    """
    router_found = False
    router_path = None
    
    for file in os.listdir(root_dir):
        filepath = os.path.join(root_dir, file)
        if (os.path.isfile(filepath) and 
            "i2pd" in file.lower() and 
            file.lower().endswith(".exe")):
            print(Fore.GREEN + f"[INFO] - Router found: {file}")
            router_found = True
            router_path = filepath
            break
    
    if not router_found:
        os.system("title I2PD SETUP - MISSING EXECUTABLE")
        print(Fore.YELLOW + "[WARNING] - No i2pd router found in this directory.")
        response = input("Would you like to autoinstall? (Y/N): ")
        
        if response.lower() in ['y', 'yes']:
            architecture = "64" if sys.maxsize > 2**32 else "32"
            print(f"[INFO] - Installing i2pd for x{architecture} architecture")
            success = install_from_github(architecture)
            
            if success:
                # Vérifier à nouveau après installation
                return check_router(root_dir)
            else:
                print(Fore.RED + "[ERROR] - Automatic installation failed")
                input("Press Enter to continue...")
                return False
        else:
            print("[INFO] - Installation cancelled.")
            input("Press Enter to continue...")
            return False
    
    return True

def check_files():
    """
    Is i2p here and working
    true or false
    """
    print("Testing i2pd installation...")
    architecture = "64" if sys.maxsize > 2**32 else "32"
    print(f"Detected architecture: x{architecture}")
    
    # Vérifier le router
    router_available = check_router()
    
    if router_available:
        print(Fore.GREEN + "[SUCCESS] - i2pd router is ready!")
        return True
    else:
        print(Fore.RED + "[WARNING] - i2pd router not available")
        return False