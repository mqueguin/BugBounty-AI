#!/usr/bin/env bash
# Quickstart iPhone / Codespace — lance la web UI et affiche le lien à ouvrir dans Safari.
set -e

cd "$(dirname "$0")"

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "❌ ANTHROPIC_API_KEY n'est pas défini."
    echo ""
    echo "Va sur https://console.anthropic.com/settings/keys"
    echo "Crée une clé, copie-la, puis ici fais :"
    echo ""
    echo "    export ANTHROPIC_API_KEY=sk-ant-..."
    echo "    bash quickstart.sh"
    echo ""
    exit 1
fi

# Génère un token si absent
if [ ! -f .web_token ]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > .web_token
    chmod 600 .web_token
fi
export BUGBOUNTY_WEB_TOKEN=$(cat .web_token)

# Prépare scope.txt si absent
if [ ! -f scope.txt ]; then
    cp scope.txt.example scope.txt
    echo "⚠  scope.txt créé vide. Ajoute tes domaines autorisés depuis la web UI."
fi

# Stoppe une instance précédente si elle tourne
pkill -f "webapp.py" 2>/dev/null || true
sleep 1

# Lance en arrière-plan
nohup python3 webapp.py --host 0.0.0.0 --port 8080 > state/webapp.log 2>&1 &
WEBAPP_PID=$!

sleep 2

# Construit l'URL selon l'environnement
if [ -n "$CODESPACE_NAME" ] && [ -n "$GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN" ]; then
    URL="https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
    LOCATION="(GitHub Codespaces)"
elif command -v hostname >/dev/null; then
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    URL="http://${IP:-localhost}:8080"
    LOCATION="(accès local)"
else
    URL="http://localhost:8080"
    LOCATION="(local)"
fi

cat <<EOF

╔════════════════════════════════════════════════════════════════╗
║  BugBounty-AI web UI — prêt $LOCATION
╠════════════════════════════════════════════════════════════════╣

  Ouvre cette URL dans Safari sur ton iPhone :

    ${URL}/?token=${BUGBOUNTY_WEB_TOKEN}

  PID du serveur : $WEBAPP_PID
  Logs : tail -f state/webapp.log
  Stop : kill $WEBAPP_PID

╚════════════════════════════════════════════════════════════════╝

EOF
