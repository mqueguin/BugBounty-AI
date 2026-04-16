# BugBounty-AI — Copilote Bug Bounty piloté par Claude

Workspace bug bounty utilisable de **trois façons** :

1. **Claude Code** (poste/laptop) — slash commands, subagents spécialisés
2. **Mode autopilot** — Claude orchestre seul recon + tri + probes + findings (Python standalone)
3. **Depuis ton téléphone (iPhone/Android)** — web UI mobile-first et/ou bot Telegram, déployé en 1-click sur Railway/Render/Fly.io

L'objectif : passer moins de temps à scroller des endpoints, et plus à trouver des failles exploitables.

> 📱 **Tu veux bosser depuis un iPhone sans terminal ?** Suis [IPHONE.md](IPHONE.md) — déploiement Railway en 10 min, ensuite tu utilises Safari + Telegram et c'est tout.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https://github.com/byAz1nee/BugBounty-AI)

---

## Trois surfaces d'utilisation

### A. Claude Code (recommandé sur poste)

```
cd BugBounty-AI
claude
```

Slash commands disponibles :

| Commande | Effet |
|----------|-------|
| `/scope-add <domain>` | Ajoute un domaine à `scope.txt` |
| `/recon <domain>` | Délègue à `recon-specialist` |
| `/hunt xss\|sqli\|idor\|ssrf\|jwt <url>` | Délègue à `vuln-hunter` |
| `/analyze <url\|file>` | Analyse vecteurs d'attaque |
| `/poc <slug>` | Génère un PoC minimal |
| `/report <slug>` | Rapport H1/Bugcrowd via `report-writer` |
| `/triage` | Classement impact/sévérité |
| `/autopilot <domain>` | **Chasse autonome complète** |
| `/serve [port]` | Lance la web UI mobile |

### B. Autopilot (Claude orchestre tout via tool use)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
echo "example.com" >> scope.txt

python3 IABounty.py --target example.com --autopilot
# OU
python3 autopilot.py --target example.com
```

Claude utilise ses propres tools pour :
- Lancer `subfinder`, `httpx`, `gau`, `paramspider`, `katana`
- Lire les outputs, prioriser les endpoints
- Lancer des probes XSS non-destructives (marqueur `xssTEST1234`)
- Écrire les findings dans `findings/<slug>.md`
- Décider quand s'arrêter via `finish()`

État persisté dans `state/current.json` (suivi temps réel possible depuis la web UI).

### C. Depuis ton téléphone

#### Option 1 : Web UI mobile-first

```bash
export BUGBOUNTY_WEB_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
python3 webapp.py --host 0.0.0.0 --port 8080
```

Puis sur ton téléphone : `http://<ip-locale-ou-tunnel>:8080/?token=<TOKEN>`

Pour exposer en HTTPS depuis l'extérieur :
```bash
cloudflared tunnel --url http://localhost:8080
# ou
ngrok http 8080
```

L'UI permet : ajouter au scope, lancer/annuler un scan (autopilot, pipeline, ou recon), voir le live status, parcourir les findings, télécharger les rapports.

#### Option 2 : Bot Telegram

```bash
# 1. Crée un bot via @BotFather, récupère le token
# 2. Récupère ton chat_id (envoie /start au bot puis :
#    https://api.telegram.org/bot<TOKEN>/getUpdates)
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_ALLOWED_CHATS=123456789  # whitelist obligatoire
export ANTHROPIC_API_KEY=sk-ant-...

pip install 'python-telegram-bot[job-queue]>=21.0'
python3 bot.py
```

Commandes du bot : `/scan <domain> [autopilot|pipeline|recon]`, `/status`, `/findings`, `/finding <slug>`, `/scope`, `/scopeadd <domain>`, `/cancel`, `/help`. Notification automatique à la fin du scan.

#### Option 3 : Termux (tout sur Android)

```bash
# Dans Termux :
pkg install git
git clone https://github.com/byAz1nee/BugBounty-AI.git
cd BugBounty-AI
bash install_termux.sh
```

Le script installe : python, go, subfinder, httpx, katana, gau, waybackurls, assetfinder, gf, dalfox, paramspider, et toutes les deps Python. Voir la fin du script pour les étapes de configuration.

---

## Installation (Linux / macOS)

```bash
git clone https://github.com/byAz1nee/BugBounty-AI.git
cd BugBounty-AI
pip install -r requirements.txt
# pip install 'python-telegram-bot[job-queue]>=21.0'   # optionnel pour le bot

# Outils Go (recon)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

cp scope.txt.example scope.txt   # puis édite avec tes domaines
```

---

## Variables d'environnement

| Var | Rôle |
|-----|------|
| `ANTHROPIC_API_KEY` | **Obligatoire** pour Claude |
| `ANTHROPIC_MODEL` | Modèle (défaut : `claude-opus-4-7`) |
| `BUGBOUNTY_WEB_TOKEN` | Token de la web UI (auto-généré si absent) |
| `TELEGRAM_BOT_TOKEN` | Token du bot Telegram |
| `TELEGRAM_ALLOWED_CHATS` | Whitelist chat_id (CSV) — refus si absent |

---

## Arborescence

```
BugBounty-AI/
├── IABounty.py              # Pipeline + entry --autopilot
├── autopilot.py             # Boucle agentique Claude
├── webapp.py                # Web UI mobile-first
├── bot.py                   # Bot Telegram
├── install_termux.sh        # Bootstrap Android
├── scope.txt[.example]      # Domaines autorisés
├── recon/                   # Outputs outils recon
├── rapport/                 # Endpoints classés, analyses
├── findings/                # Findings confirmés
│   └── _candidates/         # À valider manuellement
├── state/                   # current.json, autopilot.log, stdout.log
└── .claude/
    ├── settings.json
    ├── agents/   (4 subagents)
    ├── commands/ (9 slash commands)
    └── skills/   (5 méthodologies vuln)
```

---

## Sécurité & éthique

Le workspace n'opère **que** sur les domaines présents dans `scope.txt`. Garde-fous appliqués automatiquement :

- **Mode autopilot** : whitelist de binaires, `curl` GET/HEAD seulement, refus des patterns destructifs (`rm -rf /`, `DROP TABLE`, fork bomb, sudo, pipe-to-shell), quota 10 probes XSS, loop max 40 itérations.
- **Web UI** : auth token obligatoire, refus si la cible n'est pas dans `scope.txt`.
- **Bot Telegram** : whitelist `chat_id` obligatoire, refus si la cible n'est pas dans `scope.txt`.
- **Pipeline classique** : `--skip-scope-check` à n'utiliser qu'en CTF/lab.

`.gitignore` exclut `findings/`, `recon/`, `rapport/`, `state/`, `scope.txt`, et tous les patterns secrets (.env, .pem, id_rsa).

---

## Roadmap

- [ ] Hook post-scan : envoie notification Telegram avec top 3 findings
- [ ] Skills XXE, SSTI, RCE, LFI, GraphQL
- [ ] Dashboard avec stats cumulées (findings/jour, taux d'acceptation)
- [ ] Intégration nuclei templates custom par catégorie
- [ ] Export auto vers H1/Bugcrowd (opt-in, jamais auto-submit)
- [ ] Worker en arrière-plan pour relancer les scans périodiquement
