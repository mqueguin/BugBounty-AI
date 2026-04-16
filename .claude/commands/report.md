---
description: Transforme un finding en rapport soumissible HackerOne/Bugcrowd via report-writer
argument-hint: <finding-slug>
---

# /report $ARGUMENTS

1. Vérifie que `findings/$ARGUMENTS.md` existe. Sinon, liste les findings disponibles et demande à l'utilisateur.
2. Délègue au subagent **report-writer** avec la consigne :

> Transforme `findings/$ARGUMENTS.md` en rapport soumissible au format standard programme (H1/Bugcrowd/Intigriti).
> Produit `findings/$ARGUMENTS.submission.md`.
> Applique la checklist qualité (titre, CVSS, repro, impact, remediation).

3. Après génération, vérifie :
   - Aucun token/cookie/PII réel dans le rapport
   - CVSS vecteur présent et cohérent
   - Repro steps numérotés
   - Section Impact business-oriented
4. Affiche à l'utilisateur les 10 premières lignes du rapport + chemin du fichier.
5. Rappelle : *"Relis avant soumission. Je ne push jamais vers H1/Bugcrowd automatiquement."*
