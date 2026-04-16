---
description: Lance la chasse autonome (Claude orchestre recon + tri + probes + findings via tool use)
argument-hint: <domain> [max-iterations]
---

# /autopilot $ARGUMENTS

Mode entièrement autonome. Claude prend la cible et déroule tout seul : recon, tri, probes XSS non-destructives, écriture des findings. Tu interviens seulement pour relire les findings à la fin.

## Étapes

1. Parse `$ARGUMENTS` en `<domain> [max-iterations]`. Si `<domain>` manque, demande.
2. Vérifie que `<domain>` est dans `scope.txt`. Sinon, refuse et propose `/scope-add <domain>`.
3. Vérifie qu'`ANTHROPIC_API_KEY` est défini. Sinon, demande à l'utilisateur de l'exporter.
4. Lance :
   ```bash
   python3 IABounty.py --target <domain> --autopilot --max-iterations <N|40>
   ```
5. Pendant l'exécution, le script écrit :
   - `state/current.json` (statut, itération, findings)
   - `state/autopilot.log` (timeline des tool calls)
   - `findings/<slug>.md` (confirmés) ou `findings/_candidates/<slug>.md`
6. À la fin, affiche à l'utilisateur :
   - Le résumé Claude
   - Le nombre de findings (confirmed vs candidates)
   - La commande pour ouvrir la web UI : `python3 webapp.py --host 0.0.0.0 --port 8080`
7. Propose ensuite `/triage` pour classer, puis `/report <slug>` pour les confirmés.

## Garde-fous appliqués automatiquement par autopilot.py

- Whitelist de binaires (subfinder, httpx, gau, paramspider, katana, curl GET, jq, ...)
- `curl` limité à GET/HEAD, pas de body
- Patterns destructifs refusés (rm -rf /, DROP TABLE, fork bomb, sudo, pipe-to-shell)
- Quota de 10 probes XSS max par run
- Loop max 40 itérations (ou la valeur passée)
