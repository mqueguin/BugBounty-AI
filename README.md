# BugBounty-AI — Copilote Bug Bounty piloté par Claude Code

Workspace dédié au bug bounty, utilisable :

- **depuis Claude Code** (CLI Anthropic) grâce au dossier `.claude/` (subagents, slash commands, skills)
- **en ligne de commande** via `IABounty.py`, un pipeline recon + analyse Claude (Anthropic SDK)

Objectif : réduire le temps passé à scroller des endpoints, maximiser le temps passé à trouver des failles exploitables.

---

## Deux façons de l'utiliser

### 1. Claude Code (recommandé)

Ouvre le dossier dans [Claude Code](https://claude.com/claude-code) — tout le workflow est à portée de slash command.

```
cd BugBounty-AI
claude
```

Puis dans la session :

```
/scope-add example.com
/recon example.com
/hunt xss https://example.com/search?q=test
/poc <finding-slug>
/report <finding-slug>
/triage
```

Claude Code charge automatiquement :
- `CLAUDE.md` — règles du workspace, arborescence, workflow
- `.claude/agents/` — subagents spécialisés (`recon-specialist`, `vuln-hunter`, `report-writer`, `js-analyzer`)
- `.claude/commands/` — slash commands
- `.claude/skills/` — méthodologie par type de faille (XSS, SQLi, IDOR, SSRF, JWT)
- `.claude/settings.json` — permissions pré-configurées pour les outils recon classiques

### 2. Pipeline Python standalone

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
echo "example.com" > scope.txt

python3 IABounty.py --target example.com --claude --serve
```

Options :

| Flag | Effet |
|------|-------|
| `--target <domain>` | Domaine cible (doit être dans `scope.txt`) |
| `--claude` | Active l'analyse Claude (extraction, classification, analyse endpoint-par-endpoint) |
| `--model <id>` | Modèle Claude (défaut : `claude-opus-4-7`, override via `ANTHROPIC_MODEL` env) |
| `--vulns` | Types de failles ciblés (défaut : `xss,sqli,idor,ssrf,jwt`) |
| `--serve` | Lance le viewer Flask sur http://localhost:5000 |
| `--verbose` | Affiche chaque commande système |
| `--skip-scope-check` | **Dangereux.** À réserver aux labs/CTF. |

---

## Prérequis outils CLI

Mets ces outils dans ton PATH (via `go install` ou package manager) :

- **Recon passive** : `subfinder`, `gau`, `waybackurls`
- **Probing** : `httpx`
- **Params** : `paramspider`
- **Crawling** : `katana`
- **Optionnels actifs** (demandent confirmation dans Claude Code) : `nuclei`, `ffuf`, `sqlmap`, `dalfox`

---

## Arborescence

```
BugBounty-AI/
├── CLAUDE.md                       # Guide pour Claude Code
├── IABounty.py                     # Pipeline Python (recon + Claude)
├── requirements.txt
├── scope.txt                       # Domaines autorisés (à créer)
├── recon/                          # Outputs outils recon
├── rapport/                        # endpoints.json, classified_endpoints.json, analyse_js.md
├── findings/                       # Un .md par vulnérabilité confirmée
└── .claude/
    ├── settings.json               # Permissions & env
    ├── agents/                     # Subagents
    │   ├── recon-specialist.md
    │   ├── vuln-hunter.md
    │   ├── report-writer.md
    │   └── js-analyzer.md
    ├── commands/                   # Slash commands
    │   ├── recon.md
    │   ├── hunt.md
    │   ├── analyze.md
    │   ├── poc.md
    │   ├── report.md
    │   ├── triage.md
    │   └── scope-add.md
    └── skills/                     # Méthodologies par type de faille
        ├── xss-hunting.md
        ├── sqli-techniques.md
        ├── idor-testing.md
        ├── ssrf-bypasses.md
        └── jwt-attacks.md
```

---

## Règles éthiques (non-négociables)

Le workspace n'opère **que** sur des domaines présents dans `scope.txt`. Claude (et ses subagents) sont configurés pour :

- Refuser tout test en dehors du scope
- Éviter les actions destructives (DROP, DELETE, brute-force massif, DoS)
- Respecter les rate-limits
- Ne jamais commiter de credentials, cookies de session, ou données réelles de tiers
- Redacter PII / tokens dans les rapports

---

## Ajouter une nouvelle méthodologie

Crée un fichier dans `.claude/skills/<vuln>-<action>.md` en suivant la structure des skills existantes (identification → payloads → bypass → impact → PoC → éthique), puis ajoute le mapping dans `.claude/commands/hunt.md` si tu veux l'exposer via `/hunt <category>`.

---

## Roadmap

- [ ] Intégration `nuclei` templates custom par catégorie
- [ ] Subagent `graphql-hunter` dédié
- [ ] Export auto H1/Bugcrowd via leurs APIs (opt-in)
- [ ] Skills XXE, SSTI, RCE, LFI
- [ ] Hook post-recon qui relance automatiquement `vuln-hunter` sur le top 5
