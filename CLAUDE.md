# BugBounty-AI — Guide Claude Code

Workspace bug bounty piloté par Claude Code. Trois surfaces d'utilisation :

1. **Slash commands Claude Code** (poste/laptop)
2. **Mode autopilot** (Python autonome via `IABounty.py --autopilot` ou `autopilot.py`)
3. **Web UI mobile** (`webapp.py`) ou **bot Telegram** (`bot.py`) pour piloter depuis un téléphone

## Règles d'or (non-négociables)

1. **Scope avant tout.** Ne teste qu'un domaine listé dans `scope.txt` ou confirmé par l'utilisateur. Si absent, refuse et propose `/scope-add`.
2. **Pas de tests intrusifs non autorisés.** Pas de DoS, brute-force massif, exfiltration réelle, contournement d'auth hors scope.
3. **Trace tout.** Chaque commande recon/test produit un artefact sous `recon/`, `rapport/`, `findings/`, ou `state/`.
4. **Respect du rate-limit.** Délais raisonnables (`-rate-limit`, `-delay`) sur les outils actifs. Quota probes XSS = 10/run en autopilot.
5. **Source unique de vérité.** Les findings vont dans `findings/<slug>.md` (confirmés) ou `findings/_candidates/<slug>.md`.

## Arborescence

```
BugBounty-AI/
├── IABounty.py              # Pipeline classique + entry --autopilot
├── autopilot.py             # Boucle agentique Claude (tool use orchestrator)
├── webapp.py                # UI web mobile-first (Flask + auth token)
├── bot.py                   # Bot Telegram (whitelist obligatoire)
├── install_termux.sh        # Bootstrap Android (Termux)
├── scope.txt                # Domaines autorisés (à créer ; .gitignored)
├── recon/                   # Outputs outils recon
├── rapport/                 # Rapports JSON/Markdown générés
├── findings/                # Findings confirmés
│   └── _candidates/         # À valider manuellement
├── state/                   # current.json + autopilot.log + stdout.log
├── js/                      # Bundles JS téléchargés
└── .claude/
    ├── settings.json        # Permissions, env
    ├── agents/              # recon-specialist, vuln-hunter, report-writer, js-analyzer
    ├── commands/            # /recon /hunt /analyze /poc /report /triage /autopilot /serve /scope-add
    └── skills/              # Méthodologies XSS, SQLi, IDOR, SSRF, JWT
```

## Workflow type — depuis Claude Code

1. `/scope-add <domain>` → ajoute la cible
2. `/autopilot <domain>` → Claude orchestre tout (recon + tri + probes XSS + findings)
3. **OU** workflow manuel :
   - `/recon <domain>` → délégué à recon-specialist
   - `/hunt xss|sqli|idor|ssrf|jwt <url>` → délégué à vuln-hunter
   - `/poc <slug>` → PoC minimal
   - `/report <slug>` → rapport H1/Bugcrowd
4. `/triage` → classement impact/sévérité
5. `/serve [port]` → web UI accessible depuis ton téléphone

## Workflow depuis un téléphone

| Surface | Commande | Notes |
|---------|----------|-------|
| Web UI | `python3 webapp.py --host 0.0.0.0 --port 8080` | Auth via `BUGBOUNTY_WEB_TOKEN` ; expose via cloudflared/ngrok pour accès distant |
| Telegram | `python3 bot.py` | Whitelist `TELEGRAM_ALLOWED_CHATS` obligatoire |
| Termux | `bash install_termux.sh` puis `python3 autopilot.py --target <domain>` | Tout tourne sur Android |

## Outils CLI attendus dans le PATH

`subfinder`, `httpx`, `gau`, `waybackurls`, `paramspider`, `katana`, `nuclei`, `ffuf`, `sqlmap`, `dalfox`, `gf`, `jq`, `curl`, `dig`.

Si un outil manque, **propose l'installation** (`go install …`, `pkg install …` sur Termux, `apt install …` ailleurs) avant de bricoler un fallback.

## Modèle Claude

`claude-opus-4-7` par défaut (override via `--model` ou env `ANTHROPIC_MODEL`). Prompt caching activé sur les listes d'endpoints volumineuses (voir `IABounty.py:extract_endpoints`).

## Variables d'environnement

| Var | Rôle | Où |
|-----|------|----|
| `ANTHROPIC_API_KEY` | Obligatoire pour Claude | partout |
| `ANTHROPIC_MODEL` | Override modèle | défaut `claude-opus-4-7` |
| `BUGBOUNTY_WEB_TOKEN` | Token auth de la web UI | `webapp.py` (auto-généré si absent) |
| `TELEGRAM_BOT_TOKEN` | Token bot Telegram | `bot.py` |
| `TELEGRAM_ALLOWED_CHATS` | Whitelist `chat_id` (CSV) | `bot.py` (refus si absent) |

## Sécurité du mode autopilot

`autopilot.py` impose :
- Whitelist binaires (subfinder, httpx, gau, paramspider, katana, curl GET, jq, sort, dig, ...)
- `curl` limité à GET/HEAD, refus de `-d`/`--data`/`-T`
- Patterns destructifs refusés (rm -rf /, DROP TABLE, fork bomb, sudo, pipe-to-shell, mkfs, dd, …)
- Quota 10 probes XSS max
- Loop max 40 itérations
- Sandbox `cwd` = workspace, refus des chemins remontant hors workspace

## Ce que tu ne dois PAS faire

- Ne push **jamais** credentials, cookies, headers d'auth, ou PoC sur de vraies données utilisateur.
- Ne commit jamais `findings/` ni `recon/` ni `state/` (déjà dans `.gitignore`).
- Ne lance pas `nuclei` / `ffuf` / `sqlmap` sans confirmation explicite sur la cible.
- Ne lance pas le bot Telegram sans `TELEGRAM_ALLOWED_CHATS` (sinon n'importe qui peut le piloter).
- Ne lance pas la web UI sur `0.0.0.0` sans `BUGBOUNTY_WEB_TOKEN` (sinon UI exposée en clair).
