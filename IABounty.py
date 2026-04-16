"""
IABounty — pipeline recon + analyse bug bounty piloté par Claude.

Usage:
    python3 IABounty.py --target example.com              # recon seule
    python3 IABounty.py --target example.com --claude     # recon + analyse Claude
    python3 IABounty.py --target example.com --claude --serve  # + web viewer
"""

import argparse
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import anthropic
import requests
from flask import Flask, render_template_string, send_file

HEADERS = {"User-Agent": "Mozilla/5.0 BugBountyBot"}
DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-7")
SCOPE_FILE = Path("scope.txt")

app = Flask(__name__)


@app.route("/")
def index():
    report = Path("rapport/analyse_js.md")
    content = report.read_text(encoding="utf-8") if report.exists() else \
        "Aucun rapport généré pour l'instant. Lancez `python3 IABounty.py --target <domaine> --claude`."
    html = """
    <html>
    <head>
        <title>Copilote Bug Bounty — Rapport</title>
        <style>
            body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 2em; }
            pre { background: #2d2d2d; padding: 1em; border-radius: 8px; overflow-x: auto; }
            h1 { color: #4ec9b0; }
            a { color: #569cd6; }
        </style>
    </head>
    <body>
        <h1>Rapport d'analyse</h1>
        <p><a href="/download">Télécharger le rapport Markdown</a></p>
        <pre>{{ content }}</pre>
    </body>
    </html>
    """
    return render_template_string(html, content=content)


@app.route("/download")
def download():
    return send_file("rapport/analyse_js.md", as_attachment=True)


def run_command(cmd, verbose=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if verbose:
        print(f"[CMD] {cmd}")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"[STDERR] {result.stderr}")
    return result.stdout.strip()


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def check_scope(domain):
    """Refuse d'agir si le domaine n'est pas dans scope.txt."""
    if not SCOPE_FILE.exists():
        print(f"[!] {SCOPE_FILE} absent. Créez-le avec les domaines autorisés (un par ligne).")
        return False
    allowed = {
        line.strip().lower()
        for line in SCOPE_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    if domain.lower() not in allowed:
        print(f"[!] '{domain}' n'est pas dans {SCOPE_FILE}. Ajoutez-le avant de lancer.")
        return False
    return True


def reconnaissance(domain, verbose=False):
    print(f"[+] Reconnaissance sur {domain}")
    ensure_dir("recon")
    run_command(f"subfinder -d {domain} -silent -o recon/subdomains.txt", verbose)
    run_command("httpx -l recon/subdomains.txt -silent -o recon/live.txt", verbose)
    run_command(f"gau {domain} 2>/dev/null | sort -u > recon/gau.txt", verbose)
    run_command(f"waybackurls {domain} 2>/dev/null >> recon/gau.txt", verbose)
    run_command(f"paramspider -d {domain} -o recon/params.txt 2>/dev/null", verbose)
    run_command("katana -list recon/live.txt -jc -silent -o recon/katana.txt", verbose)

    combined = ""
    for fname in ("recon/live.txt", "recon/gau.txt", "recon/params.txt", "recon/katana.txt"):
        if Path(fname).exists():
            combined += Path(fname).read_text(errors="ignore") + "\n"
    Path("recon/all_urls.txt").write_text(combined)
    return combined


def claude_client():
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY non défini dans l'environnement.")
    return anthropic.Anthropic()


def extract_endpoints(client, domain, recon_text, vuln_types):
    """Extrait les endpoints intéressants via Claude, avec prompt caching sur la recon brute."""
    print("[+] Extraction des endpoints prioritaires (Claude)...")
    recon_text = recon_text[:100_000]  # garde ~25k tokens max

    system = (
        "Tu es un expert en sécurité web spécialisé bug bounty. "
        "Tu analyses des artefacts de reconnaissance et retournes uniquement un JSON valide, "
        "sans prose ni markdown, sans ```."
    )

    user_prompt = f"""Voici les URLs collectées pour {domain} :

<recon>
{recon_text}
</recon>

Extrais les endpoints les plus prometteurs pour un test de sécurité
(APIs, URLs paramétrées, admin, upload, redirect, fichiers sensibles...).
Types de failles visées : {', '.join(vuln_types)}.

Retourne UNIQUEMENT un JSON de la forme :
{{
  "endpoints": ["https://...", "https://..."],
  "notes": "phrase courte sur la surface d'attaque"
}}"""

    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=16_000,
        system=system,
        cache_control={"type": "ephemeral"},
        messages=[{"role": "user", "content": user_prompt}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    ensure_dir("rapport")
    Path("rapport/endpoints.json").write_text(text)
    try:
        return json.loads(text).get("endpoints", [])
    except json.JSONDecodeError:
        print("[!] Réponse Claude non-JSON, fichier brut sauvegardé dans rapport/endpoints.json")
        return []


def classify_endpoints(client, endpoints):
    print("[+] Classification des endpoints (Claude)...")
    system = (
        "Tu es un expert en sécurité web. Classe les URLs dans des catégories d'attaque. "
        "Réponds uniquement avec un JSON valide."
    )
    user_prompt = f"""Classe les URLs suivantes dans ces catégories :
api_private, api_public, admin_like, auth, upload, download, redirect,
assets, well_known, xss_candidate, sqli_candidate, idor_candidate, ssrf_candidate, others.

Une URL peut apparaître dans plusieurs catégories si pertinent.

URLs :
{json.dumps(endpoints[:200], indent=2)}

Retourne UNIQUEMENT un JSON {{ "<categorie>": ["url", ...], ... }}."""

    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=16_000,
        system=system,
        messages=[{"role": "user", "content": user_prompt}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    Path("rapport/classified_endpoints.json").write_text(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print("[!] Classification non-JSON, rapport/classified_endpoints.json contient la réponse brute.")
        return {}


def analyze_endpoints(client, categories, vuln_types):
    print("[+] Analyse individuelle des endpoints prioritaires (Claude)...")
    result = []
    system = (
        "Tu es un expert en sécurité web offensive. "
        "Pour chaque endpoint, tu produis une analyse courte, structurée, actionnable."
    )

    for category, urls in categories.items():
        for url in urls[:3]:
            user_prompt = f"""Endpoint à analyser : {url}
Catégorie déduite : {category}
Types de failles visées : {', '.join(vuln_types)}

Produis une analyse Markdown avec ces sections exactement :

### Fonctionnalité probable
1-2 phrases.

### Failles plausibles (par ordre de probabilité)
- Type — raison courte

### Test manuel suggéré (1 seule requête curl)
```
curl ...
```

### Note bug bounty
Score /10 et justification en 1 ligne."""

            try:
                response = client.messages.create(
                    model=DEFAULT_MODEL,
                    max_tokens=2_000,
                    system=system,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                text = next((b.text for b in response.content if b.type == "text"), "")
                result.append(f"## {url}\n\n_Catégorie : {category}_\n\n{text}\n")
            except anthropic.APIError as exc:
                result.append(f"## {url}\n\n_Erreur Claude : {exc}_\n")

    ensure_dir("rapport")
    Path("rapport/analyse_js.md").write_text("\n\n".join(result), encoding="utf-8")
    print(f"[+] {len(result)} endpoints analysés dans rapport/analyse_js.md")


def test_xss_reflected(base_url, verbose=False):
    """Test XSS reflecté non-destructif : injecte un marqueur inoffensif."""
    marker = "xssTEST1234"
    try:
        parsed = urlsplit(base_url)
        query = parse_qs(parsed.query)
        if not query:
            return False
        for param in query:
            new_query = {**query, param: marker}
            encoded = urlencode(new_query, doseq=True)
            test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, parsed.fragment))
            if verbose:
                print(f"[XSS probe] {test_url}")
            resp = requests.get(test_url, headers=HEADERS, timeout=10)
            if marker in resp.text:
                print(f"[!] Marqueur reflété via '{param}' sur {base_url} — candidat XSS à vérifier manuellement.")
                return True
    except requests.RequestException as exc:
        print(f"[XSS probe error] {exc}")
    return False


def parse_args():
    parser = argparse.ArgumentParser(description="Copilote Bug Bounty — pipeline Claude")
    parser.add_argument("--target", required=True, help="Domaine cible (doit être dans scope.txt)")
    parser.add_argument("--vulns", default="xss,sqli,idor,ssrf,jwt",
                        help="Types de failles à viser (virgule)")
    parser.add_argument("--claude", action="store_true",
                        help="Pipeline classique : recon + analyse Claude (nécessite ANTHROPIC_API_KEY)")
    parser.add_argument("--autopilot", action="store_true",
                        help="Mode autonome : Claude orchestre recon + tri + probes + findings via tool use")
    parser.add_argument("--max-iterations", type=int, default=40,
                        help="Plafond d'itérations en mode autopilot (défaut : 40)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Modèle Claude (défaut : {DEFAULT_MODEL}, override par ANTHROPIC_MODEL)")
    parser.add_argument("--serve", action="store_true",
                        help="Lancer le viewer Flask local à la fin (legacy ; utilise webapp.py pour le mobile)")
    parser.add_argument("--skip-scope-check", action="store_true",
                        help="Ne pas vérifier scope.txt (à utiliser en CTF/lab uniquement)")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    global DEFAULT_MODEL
    DEFAULT_MODEL = args.model

    if not args.skip_scope_check and not check_scope(args.target):
        return 1

    if args.autopilot:
        from autopilot import run_autopilot
        print(f"[+] Autopilot lancé sur {args.target}")
        final_state = run_autopilot(
            args.target, workspace=".", model=args.model,
            max_iterations=args.max_iterations,
        )
        print(json.dumps(final_state, indent=2))
        if args.serve:
            print("[+] Viewer (legacy) : http://localhost:5000")
            app.run(host="127.0.0.1", port=5000, debug=False)
        return 0 if final_state.get("status") == "done" else 2

    vuln_types = [v.strip() for v in args.vulns.split(",") if v.strip()]
    recon_text = reconnaissance(args.target, args.verbose)

    if args.claude:
        client = claude_client()
        endpoints = extract_endpoints(client, args.target, recon_text, vuln_types)
        if endpoints:
            categories = classify_endpoints(client, endpoints)
            if categories:
                analyze_endpoints(client, categories, vuln_types)

    if args.serve:
        print("[+] Viewer (legacy) : http://localhost:5000")
        print("[+] Pour la version mobile : python3 webapp.py --host 0.0.0.0 --port 5000")
        app.run(host="127.0.0.1", port=5000, debug=False)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
