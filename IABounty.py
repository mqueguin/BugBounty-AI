import os
import subprocess
import requests
import re
import argparse
import json
from openai import OpenAI
from urllib.parse import urlencode, parse_qs, urlsplit, urlunsplit
from pathlib import Path
from flask import Flask, render_template_string, send_file

HEADERS = {'User-Agent': 'Mozilla/5.0 BugBountyBot'}
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY)

parser = argparse.ArgumentParser(description="Copilote Bug Bounty AI")
parser.add_argument("--target", required=True, help="Cible à scanner (ex: example.com)")
parser.add_argument("--threads", type=int, default=10, help="Nombre de threads (futur usage)")
parser.add_argument("--vulns", default="xss,sqli,idor,csrf", help="Types de failles à rechercher")
parser.add_argument("--verbose", action="store_true", help="Afficher la sortie complète des commandes système")
args = parser.parse_args()

TARGET_DOMAIN = args.target
VULN_TYPES = args.vulns.split(",")

app = Flask(__name__)

@app.route('/')
def index():
    if os.path.exists("rapport/analyse_js.md"):
        with open("rapport/analyse_js.md", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "Aucun rapport généré pour l'instant. Lancez l'analyse."
    html_template = f"""
    <html>
        <head>
            <title>Copilote Bug Bounty - Rapport</title>
            <style>
                body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 2em; }}
                pre {{ background: #2d2d2d; padding: 1em; border-radius: 8px; overflow-x: auto; }}
                h1 {{ color: #4ec9b0; }}
            </style>
        </head>
        <body>
            <h1>Rapport d'Analyse JS</h1>
            <pre>{content}</pre>
        </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/download')
def download():
    return send_file("rapport/analyse_js.md", as_attachment=True)

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if args.verbose:
        print(f"[VERBOSE] Command: {cmd}")
        print(result.stdout)
        if result.stderr:
            print(f"[STDERR] {result.stderr}")
    return result.stdout.strip()


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def ensure_file_exists(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("")

def reconnaissance(domain):
    print("[+] Reconnaissance étendue...")
    ensure_dir("recon")
    subdomains = run_command(f"subfinder -d {domain} -silent")
    with open("recon/subdomains.txt", "w") as f:
        f.write(subdomains)
    run_command("httpx-toolkit -l recon/subdomains.txt -silent -o recon/urls.txt")
    run_command(f"gau {domain} | sort -u > recon/gau.txt")
    run_command(f"waybackurls {domain} >> recon/gau.txt")
    run_command(f"paramspider -d {domain} > recon/params.txt")
    run_command(f"katana -list recon/subdomains.txt -jc -o recon/katana.txt")

    combined_text = ""
    for file in ["recon/urls.txt", "recon/gau.txt", "recon/params.txt", "recon/katana.txt"]:
        if os.path.exists(file):
            with open(file) as f:
                combined_text += f.read() + "\n"

    prompt = f"""
Tu es un expert en sécurité web. Voici un ensemble d'URLs collectées lors d'une phase de reconnaissance pour le domaine {domain} :

{combined_text[:10000]}

Identifie et extrait uniquement les endpoints intéressants pour un test de sécurité (ex: APIs, URLs dynamiques, interfaces d'administration, endpoints exposant des paramètres sensibles, etc.). Fournis une liste JSON de ces endpoints (uniquement les endpoints je ne veux pas de phrases ou mots supplémentaires).
"""

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        gpt_result = response.choices[0].message.content
        ensure_dir("rapport")
        with open("rapport/endpoints.json", "w") as f:
            f.write(gpt_result)
    except Exception as e:
        print(f"[GPT Error] {e}")

def classify_endpoints_with_openai():
    print("[+] Classification des endpoints avec OpenAI...")
    with open("rapport/endpoints.json") as f:
        endpoints = json.load(f)

    prompt = f"""
Tu es un expert en sécurité web. Classe les URLs suivantes dans les catégories suivantes : api_private, api_public, admin_like, assets, downloads, well_known, feeds, others, XSS, IDOR, SQLI. Retourne un JSON avec ces clés comme propriétés et des listes de liens comme valeurs.

{json.dumps(endpoints[:100], indent=2)}
"""
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        gpt_output = response.choices[0].message.content
        ensure_dir("rapport")
        with open("rapport/classified_endpoints.json", "w") as f:
            f.write(gpt_output)
        print("[+] Classification terminée dans rapport/classified_endpoints.json")
    except Exception as e:
        print(f"[GPT Error] {e}")

def test_xss_payloads_adaptatif(base_url):
    print(f"[TEST XSS] Analyse adaptative sur : {base_url}")
    payloads = [
        "<script>alert(1)</script>",
        "\"'><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>"
    ]
    try:
        parsed = urlsplit(base_url)
        query = parse_qs(parsed.query)
        if not query:
            print("[XSS] Aucun paramètre détecté dans l'URL, skip.")
            return False
        for param in query:
            for payload in payloads:
                new_query = query.copy()
                new_query[param] = payload
                encoded = urlencode(new_query, doseq=True)
                new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, parsed.fragment))
                print(f"[XSS] Test URL: {new_url}")
                resp = requests.get(new_url, headers=HEADERS, timeout=10)
                if payload in resp.text:
                    print(f"[!!] XSS détectée via paramètre '{param}' avec payload : {payload}")
                    return True
    except Exception as e:
        print(f"[XSS Error] {e}")
    return False

def analyze_js_files():
    print("[+] Analyse des endpoints classés avec GPT...")
    result = ""
    with open("rapport/classified_endpoints.json") as f:
        categories = json.load(f)
    for category, urls in categories.items():
        for url in urls[:2]:
            prompt = f"""
Tu es un expert en sécurité web. Voici un endpoint à analyser : {url}
- Tente de deviner sa fonctionnalité (login, API privée, fichier sensible...)
- Identifie les failles potentielles : {', '.join(VULN_TYPES)}
- Suggère un vecteur d'attaque et un PoC simplifié
- Donne une note de 1 à 10 sur le potentiel en bug bounty
"""
            try:
                chat_response = openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                )
                gpt_output = chat_response.choices[0].message.content
                result += f"\n\n# Analyse de {url}\n{gpt_output}\n"
            except Exception as e:
                result += f"\n\n# Erreur GPT sur {url} : {e}\n"
    with open("rapport/analyse_js.md", "w", encoding="utf-8") as f:
        f.write(result)

def main():
    ensure_dir("js")
    reconnaissance(TARGET_DOMAIN)
    classify_endpoints_with_openai()
    analyze_js_files()
    print("[+] Rapport généré : rapport/analyse_js.md")
    print("[+] Lancement de l'interface web sur http://localhost:5000")
    app.run(debug=False)

if __name__ == "__main__":
    main()

