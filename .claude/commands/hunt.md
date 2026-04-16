---
description: Chasse un type de vulnérabilité sur une cible en déléguant au vuln-hunter
argument-hint: <xss|sqli|idor|ssrf|jwt|redirect|ssti|xxe> <url>
---

# /hunt $ARGUMENTS

Parse `$ARGUMENTS` en `<category> <url>`. Si l'un des deux manque, demande.

## Étapes

1. **Charge la skill** correspondant à `<category>` depuis `.claude/skills/` :
   - `xss` → `xss-hunting.md`
   - `sqli` → `sqli-techniques.md`
   - `idor` → `idor-testing.md`
   - `ssrf` → `ssrf-bypasses.md`
   - `jwt` → `jwt-attacks.md`
   - (autres : adapte avec la skill la plus proche ou ton savoir général)

2. **Délègue au subagent `vuln-hunter`** avec la consigne :

> Cible : `<url>`. Type de faille à chasser en priorité : `<category>`.
> Applique la méthode décrite dans `.claude/skills/<skill-file>.md`.
> Limite à 10 requêtes actives max. Aucun payload destructif.
> Si tu confirmes la faille, écris `findings/<slug>.md` au format template.
> Sinon, écris `findings/_candidates/<slug>.md` avec tes observations.

3. **Résumé final** à l'utilisateur :
   - Statut : ✅ Confirmed / 🟡 Suspected / ❌ Ruled out
   - Chemin du finding file
   - Action suivante suggérée (souvent : `/report <slug>` si confirmed)
