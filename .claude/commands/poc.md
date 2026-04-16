---
description: Génère un PoC minimal reproductible pour une vulnérabilité confirmée
argument-hint: <finding-slug-or-url> [vuln-type]
---

# /poc $ARGUMENTS

Objectif : produire le PoC le plus court et reproductible possible pour une vuln.

## Étapes

1. Si `$ARGUMENTS` correspond à un fichier `findings/<slug>.md` existant, lis-le pour récupérer le contexte (url, type, param).
2. Sinon, demande à l'utilisateur de préciser (url, type de vuln, paramètre concerné).
3. Construis le PoC selon le type :

### XSS
- Commande `curl` minimale déclenchant le payload
- HTML page PoC (`findings/<slug>.poc.html`) pour DOM/Blind XSS
- Fallback Burp Collaborator si Blind

### SQLi
- Boolean-based : 2 requêtes (TRUE/FALSE) avec diff observable
- Time-based : 1 requête avec `SLEEP(5)` (ou équivalent DBMS) + mesure du temps

### IDOR
- Deux requêtes : user A (légitime) et user A accédant à la ressource de user B
- Diff des réponses, prouver l'accès non-autorisé

### SSRF
- Requête avec URL interne (`http://169.254.169.254/`, `http://localhost:22`)
- Indicateur de succès (timing, body, header leak)

### JWT
- Script Python minimal avec `jwt` / `pyjwt` pour forger le token
- Requête avec le token forgé + réponse prouvant l'escalation

## Output

- Le PoC (commande ou snippet) dans le finding file, section `## PoC`
- Un fichier externe `findings/<slug>.poc.<ext>` si besoin (html, py, sh)
- Le PoC doit tourner en **< 10 secondes** et **sans toucher à de vraies données**

## Règles

- Redact les tokens/cookies/PII réels avant commit
- Jamais de payload destructif (DROP, DELETE, rm)
- Jamais d'écriture sur le système cible
