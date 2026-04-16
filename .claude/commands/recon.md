---
description: Lance la phase de reconnaissance complète sur un domaine via le subagent recon-specialist
argument-hint: <domain>
---

# /recon $ARGUMENTS

1. Vérifie que `$ARGUMENTS` est présent dans `scope.txt`. Si le fichier n'existe pas, demande à l'utilisateur de le créer puis refuse de continuer.
2. Délègue au subagent **recon-specialist** avec cette consigne :

> Domaine cible : `$ARGUMENTS`. Exécute la phase recon complète (subdomain enum passif, résolution httpx, collecte gau/waybackurls, extraction paramspider, crawl katana). Dédupliquer dans `recon/all_urls.txt`. Classifier dans `rapport/classified_endpoints.json`. Produire `rapport/priority.md` avec les 20 endpoints les plus prometteurs. Respecter le scope, aucun test actif de vuln.

3. Quand l'agent rend la main, résume à l'utilisateur :
   - Nombre de sous-domaines trouvés / vivants
   - Top 5 endpoints prioritaires avec justification 1-ligne
   - Next step suggéré (souvent : `/hunt <category> <url>` sur le top endpoint)
