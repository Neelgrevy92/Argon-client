from playwright.sync_api import sync_playwright
import requests
from bs4 import BeautifulSoup
import random
from urllib.parse import urlparse, parse_qs
import csv 


# Proxy HTTP fourni par I2Pd
PROXIES = {
    "http": "http://127.0.0.1:4444",
    "https": "http://127.0.0.1:4444"
}
BASE_URL = "http://inr.i2p/browse/"


def fetch_registry(page: int = 0):
    """Télécharge et parse une page du registre I2P."""
    try:
        url = BASE_URL if page == 0 else f"{BASE_URL}?page={page}&order=name"
        resp = requests.get(url, proxies=PROXIES, timeout=180)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"[ERREUR] Impossible de récupérer la page {page} : {e}")
        return None


def parse_sites(soup):
    """Extrait les sites d'un objet BeautifulSoup."""
    if not soup:
        return []

    rows = soup.find_all("tr")
    sites = []

    for row in rows:
        a = row.find("a")
        if a and ".i2p" in a.text:
            sites.append({
                "name": a.text.strip(),
                "url": a["href"].strip()
            })
    return sites


def get_sites(page: int = 0, pick_random: bool = False):
    """Récupère les sites du registre (page spécifique ou aléatoire)."""
    if pick_random:
        random_page = random.randint(1, 28)
        soup = fetch_registry(random_page)
        sites = parse_sites(soup)
        return [random.choice(sites)] if sites else []
    else:
        soup = fetch_registry(page)
        return parse_sites(soup)


def print_sites_cli(sites):
    """Affiche les sites dans le terminal avec hyperliens ANSI cliquables."""
    for s in sites:
        print(f"\033]8;;{s['url']}\033\\{s['name']}\033]8;;\033\\")


def browse_site(url):
    """Ouvre un eepsite avec Playwright via I2P."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, proxy={"server": PROXIES["http"]})
        page = browser.new_page()
        try:
            page.goto(url, timeout=120_000)  # 120s
            input("Appuyez sur Entrée pour fermer...")
        except Exception as e:
            print("Erreur lors du chargement du site :", e)
        finally:
            browser.close()


def registry_to_file(filename="registry.csv"):
    """Extrait les 28 pages du registre et les enregistre dans un CSV."""
    all_sites = []

    for page in range(28):
        print(f"[INFO] Récupération de la page {page}...")
        sites = get_sites(page=page)
        for s in sites:
            parsed_url = urlparse(s["url"])
            params = parse_qs(parsed_url.query)
            dest = params.get("i2paddresshelper", [""])[0]

            all_sites.append({
                "Name": s["name"],
                "Dest": dest
            })

    # Sauvegarde CSV
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Name", "Dest"])
        writer.writeheader()
        writer.writerows(all_sites)

    print(f"[OK] {len(all_sites)} sites enregistrés dans {filename}")



if __name__ == "__main__":

    registry_to_file("i2p_registry.csv")


    """
    # Exemple 1 : récupérer la première page
    sites = get_sites()
    print_sites_cli(sites)

    # Exemple 2 : récupérer un site aléatoire
    rand_site = get_sites(pick_random=True)
    if rand_site:
        print("\n[Site aléatoire]")
        print_sites_cli(rand_site)
        browse_site(BASE_URL)
        # Lancer dans Playwright si on veut tester
    """    
