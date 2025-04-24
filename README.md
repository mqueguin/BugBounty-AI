# 🤖 Bug Bounty Copilot AI

Un agent IA semi-autonome pour le bug bounty qui t’assiste de A à Z : reconnaissance, tri intelligent des endpoints, analyse automatique avec GPT, génération de PoC et interface web pour visualiser les résultats.

> ✨ Conçu pour que tu passes moins de temps à scroller les endpoints et plus de temps à **trouver des failles exploitables.**

---

## 🚀 Fonctionnalités

- 🔍 **Reconnaissance étendue** (subdomains, historical URLs, paramètres, etc.)
- 🧠 **Classification automatique** des endpoints via GPT (admin, APIs, assets…)
- 🛠️ **Analyse automatique** des endpoints ou fichiers JS avec PoC potentiels
- 📊 **Interface web** locale avec rapport Markdown généré automatiquement
- 🧪 **Tests actifs** (bientôt : XSS, IDOR, SQLi…)
- 🧵 **Options CLI** (threads, types de failles ciblées, verbose…)

---

## ⚙️ Installation

### 1. Clone le projet

```bash
git clone https://github.com/tonpseudo/bugbounty-copilot-ai.git
cd bugbounty-copilot-ai
```

2. Installe les dépendances Python
```bash
pip install -r requirements.txt
```
3. Assure-toi d’avoir les outils CLI installés

    subfinder

    httpx

    gau

    waybackurls

    paramspider

    Tu peux les installer facilement avec go install ou apt install.

4. Configure ta clé OpenAI
```bash
export OPENAI_API_KEY=ta-cle-api-openai
```
🧠 Utilisation
Lancer une analyse complète sur un domaine
```bash
python3 main.py --target example.com
```

Mode verbose (affiche les commandes en cours)
```bash
python3 main.py --target example.com --verbose
```
Spécifier les failles ciblées
```bash
python3 main.py --target example.com --vulns xss,sqli,idor
```
📁 Structure du projet

├── js/                        # JS téléchargés automatiquement
├── recon/                     # Fichiers de reconnaissance
├── rapport/
│   ├── endpoints.json         # Tous les endpoints bruts
│   ├── classified_endpoints.json  # Classés par catégories via GPT
│   └── analyse_js.md          # Rapport final généré
├── main.py                    # Fichier principal

🛠️ Roadmap à venir

Tests actifs XSS/IDOR/SQLi par catégorie

Génération de rapports Markdown prêts à soumettre

Mode “Autopilot full scan”

Intégration LinkFinder pour enrichir les analyses JS

Intégration à Discord / Slack
