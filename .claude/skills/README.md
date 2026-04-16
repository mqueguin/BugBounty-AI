# Bibliothèque de skills vulnérabilités

Références de méthodologie par type de faille. Les subagents `vuln-hunter` et `js-analyzer` les chargent à la demande.

| Skill | Fichier |
|-------|---------|
| XSS (reflected/stored/DOM) | [`xss-hunting.md`](./xss-hunting.md) |
| SQL Injection | [`sqli-techniques.md`](./sqli-techniques.md) |
| IDOR / BOLA | [`idor-testing.md`](./idor-testing.md) |
| SSRF | [`ssrf-bypasses.md`](./ssrf-bypasses.md) |
| JWT | [`jwt-attacks.md`](./jwt-attacks.md) |

## Comment ajouter une skill

1. Nomme le fichier `<slug>-<action>.md` (ex: `xxe-exploitation.md`, `ssti-payloads.md`)
2. Structure attendue :
   - Section 1 : identifier les candidats
   - Section 2 : payloads / techniques
   - Section 3 : bypass de filtres
   - Section 4 : impact et sévérité
   - Section 5 : format PoC pour le rapport
   - Section 6 : règles éthiques
3. Référence-la depuis `.claude/commands/hunt.md` si tu veux l'activer via `/hunt <category>`.

## Sources de référence

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide v4](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.wiki/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
