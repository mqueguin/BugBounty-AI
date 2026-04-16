---
description: Ajoute un ou plusieurs domaines au fichier scope.txt
argument-hint: <domain1> [domain2 ...]
---

# /scope-add $ARGUMENTS

1. Si `scope.txt` n'existe pas, crée-le avec un header :
   ```
   # Domaines autorisés. Un par ligne. Commentaires avec #.
   # Mis à jour le : <date>
   ```
2. Pour chaque domaine dans `$ARGUMENTS` :
   - Normalise (lowercase, strip protocol, strip trailing `/`)
   - Vérifie qu'il n'est pas déjà présent
   - Ajoute-le
3. Affiche le `scope.txt` mis à jour.
4. Rappelle : *"Vérifie que ces domaines sont bien dans le programme bug bounty officiel (pas juste un sous-domaine qu'on croit autorisé)."*
