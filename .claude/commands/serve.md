---
description: Lance la web UI mobile pour piloter BugBounty-AI depuis un téléphone
argument-hint: [port]
---

# /serve $ARGUMENTS

1. Si `BUGBOUNTY_WEB_TOKEN` est absent, génère un token et exporte-le :
   ```bash
   export BUGBOUNTY_WEB_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
   ```
2. Choisis le port : `$ARGUMENTS` ou `8080` par défaut.
3. Lance la webapp en arrière-plan :
   ```bash
   python3 webapp.py --host 0.0.0.0 --port <PORT>
   ```
4. Affiche à l'utilisateur :
   - L'URL locale : `http://localhost:<PORT>/?token=<TOKEN>`
   - L'URL LAN (`hostname -I` puis `http://<ip>:<PORT>/?token=<TOKEN>`)
   - Comment exposer en HTTPS pour accès distant : `cloudflared tunnel --url http://localhost:<PORT>` ou `ngrok http <PORT>`
5. **Sécurité** : rappelle que sans token l'UI est inaccessible, et que le token doit rester privé.
