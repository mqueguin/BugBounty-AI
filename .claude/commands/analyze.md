---
description: Analyse un endpoint, une requête HTTP ou un fichier JS pour identifier les vecteurs d'attaque
argument-hint: <url|file-path>
---

# /analyze $ARGUMENTS

Prend l'input `$ARGUMENTS` et détermine son type :

- **URL** (commence par `http`) → délègue à **vuln-hunter** pour analyse multi-vecteurs.
- **Fichier `.js`** ou dossier contenant des `.js` → délègue à **js-analyzer**.
- **Fichier texte** (requête HTTP brute, réponse, log) → analyse directement en utilisant les skills pertinentes.

Output attendu :
- Liste des vecteurs d'attaque plausibles, classés par probabilité
- Pour chaque vecteur : 1 test concret à faire (commande curl ou étape Burp)
- Recommandation de la prochaine commande (`/hunt <cat> <url>` en général)

Ne lance **aucun** test actif dans cette commande — c'est juste de l'analyse statique.
