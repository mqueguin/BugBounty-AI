# BugBounty-AI — Guide Claude Code

Ce workspace est un copilote bug bounty piloté par Claude Code. Ton rôle : accélérer la reconnaissance, l'analyse de vulnérabilités, la rédaction de PoC et la soumission de rapports.

## Règles d'or

1. **Scope avant tout.** Ne teste qu'un domaine explicitement listé dans `scope.txt` ou confirmé par l'utilisateur. Si absent, demande.
2. **Pas de tests intrusifs non autorisés.** Pas de DoS, brute-force massif, exfiltration réelle de données, ni contournement d'authentification hors scope.
3. **Trace tout.** Chaque commande recon/test produit un artefact sous `recon/`, `rapport/`, ou `findings/`.
4. **Respect du rate-limit.** Utilise des délais raisonnables (`-rate-limit`, `-delay`) sur les outils actifs.
5. **Source unique de vérité.** Les findings vont dans `findings/<id>.md` avec un template standard (voir `.claude/commands/report.md`).

## Arborescence attendue

```
BugBounty-AI/
├── IABounty.py              # Pipeline Python (recon + analyse Claude)
├── scope.txt                # Domaines autorisés (à créer par l'utilisateur)
├── recon/                   # Outputs bruts des outils recon
├── rapport/                 # Rapports générés (JSON, Markdown)
├── findings/                # Un fichier Markdown par vulnérabilité confirmée
├── js/                      # Fichiers JS téléchargés pour analyse
└── .claude/
    ├── agents/              # Subagents (recon, vuln-hunter, report-writer)
    ├── commands/            # Slash commands (/recon, /hunt, /poc, /report)
    └── skills/              # Références vuln (XSS, SQLi, IDOR, SSRF, JWT)
```

## Workflow type

1. `/recon <domain>` → lance la phase passive + active, produit `recon/*.txt`.
2. Délègue à l'agent **recon-specialist** pour trier les endpoints intéressants.
3. `/hunt xss|sqli|idor|ssrf|jwt <url>` → délègue au **vuln-hunter** qui applique la skill pertinente.
4. `/poc <url> <vuln>` → PoC minimal reproductible.
5. `/report <finding-id>` → rapport HackerOne/Bugcrowd via **report-writer**.
6. `/triage` → classement impact/sévérité des findings en attente.

## Outils CLI attendus dans le PATH

`subfinder`, `httpx` (ou `httpx-toolkit`), `gau`, `waybackurls`, `paramspider`, `katana`, `nuclei`, `ffuf`, `sqlmap`, `dalfox`, `gf`, `jq`, `curl`.

Si un outil manque, **propose l'installation** (`go install …`, `apt install …`) avant de bricoler un fallback.

## Modèle Claude

Le pipeline Python utilise `claude-sonnet-4-6` par défaut (override via `--model`). Active le prompt caching sur les listes d'endpoints volumineuses (voir `IABounty.py`).

## Variables d'environnement

- `ANTHROPIC_API_KEY` — obligatoire pour `IABounty.py`
- `ANTHROPIC_MODEL` — optionnel, défaut `claude-sonnet-4-6`

## Ce que tu ne dois PAS faire

- Ne push **jamais** de credentials, cookies, headers d'auth, ou PoC exploitant de vraies données utilisateur dans git.
- Ne commit jamais le dossier `findings/` s'il contient des détails non publics d'un programme privé. Le `.gitignore` l'exclut par défaut.
- Ne lance pas `nuclei` / `ffuf` / `sqlmap` sans confirmation explicite de l'utilisateur sur la cible.
