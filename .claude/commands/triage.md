---
description: Classe les findings en attente par impact, sévérité, et probabilité d'acceptation
---

# /triage

1. Liste les findings avec `ls findings/*.md` (exclure `_candidates/`, `_log.md`).
2. Pour chaque finding, extrais :
   - Titre
   - Type de vuln
   - Sévérité annoncée
   - Cible (asset)
3. Charge `rapport/priority.md` s'il existe (priorisation recon).
4. Produit un tableau trié :

| Slug | Type | Sévérité | CVSS | Impact estimé | Risque dup | Statut |
|------|------|----------|------|---------------|------------|--------|
| ... | XSS | High | 7.4 | Session hijack | Low | ✅ Ready |

5. Pour chaque finding :
   - **Ready** : finding + submission existent, PoC testé
   - **Needs PoC** : finding existe, pas de `.poc.*` ni section PoC complète
   - **Needs submission** : finding OK, pas de `.submission.md`
   - **Draft** : brouillon, incomplet

6. Propose un ordre de soumission (gros impact d'abord, uniques avant communs, duplicate-risky en dernier).

7. Ne soumet **rien** automatiquement. Output = tableau + recommandation d'ordre.
