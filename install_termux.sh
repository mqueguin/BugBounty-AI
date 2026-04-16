#!/data/data/com.termux/files/usr/bin/env bash
#
# Bootstrap BugBounty-AI sur Android Termux.
# Installe : python, go, outils recon (subfinder/httpx/gau/waybackurls/katana/paramspider),
# puis les deps Python (anthropic, flask, requests, python-telegram-bot).
#
# Usage :
#   curl -sSL <raw-url>/install_termux.sh | bash
# ou
#   bash install_termux.sh
#
# Après install, configure :
#   export ANTHROPIC_API_KEY=sk-ant-...
#   export BUGBOUNTY_WEB_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
#   echo "<TOKEN>" > .web_token   # pour le retrouver
#
# Puis lance :
#   python3 webapp.py --host 0.0.0.0 --port 8080
# et ouvre http://localhost:8080/?token=<TOKEN> dans Chrome sur le téléphone.

set -e

if [ ! -d "/data/data/com.termux" ]; then
    echo "[!] Ce script est conçu pour Termux (Android). Utilise install.sh sur Linux/macOS."
    exit 1
fi

echo "[+] Mise à jour des paquets Termux"
pkg update -y && pkg upgrade -y

echo "[+] Installation des dépendances de base"
pkg install -y python python-pip git curl wget golang openssh termux-api jq

echo "[+] Configuration GOPATH"
mkdir -p ~/go/{bin,src,pkg}
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# Persiste dans .bashrc / .zshrc
for rc in ~/.bashrc ~/.zshrc; do
    if [ -f "$rc" ] && ! grep -q "GOPATH=" "$rc"; then
        cat >> "$rc" <<'EOF'

# BugBounty-AI - Go tools path
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
EOF
    fi
done

echo "[+] Installation des outils recon Go"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/hahwul/dalfox/v2@latest"
)
for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%@*}")
    if command -v "$name" >/dev/null 2>&1; then
        echo "  - $name déjà installé"
    else
        echo "  - go install $tool"
        go install "$tool" || echo "    ⚠ $name a échoué (pas bloquant)"
    fi
done

echo "[+] Installation paramspider (Python)"
if [ ! -d ~/ParamSpider ]; then
    git clone https://github.com/devanshbatham/ParamSpider.git ~/ParamSpider
    pip install -r ~/ParamSpider/requirements.txt
    # Wrapper minimal dans le PATH
    cat > "$PREFIX/bin/paramspider" <<EOF
#!/data/data/com.termux/files/usr/bin/env bash
python3 "$HOME/ParamSpider/paramspider.py" "\$@"
EOF
    chmod +x "$PREFIX/bin/paramspider"
fi

echo "[+] Détection du dossier BugBounty-AI"
if [ -f "./IABounty.py" ]; then
    PROJECT_DIR="$(pwd)"
elif [ -d ~/BugBounty-AI ]; then
    PROJECT_DIR="$HOME/BugBounty-AI"
    cd "$PROJECT_DIR"
else
    echo "[+] Clonage du dépôt"
    git clone https://github.com/byAz1nee/BugBounty-AI.git ~/BugBounty-AI
    cd ~/BugBounty-AI
    PROJECT_DIR="$HOME/BugBounty-AI"
fi

echo "[+] Installation des deps Python"
pip install --upgrade pip
pip install -r requirements.txt
pip install "python-telegram-bot[job-queue]>=21.0" || echo "  ⚠ python-telegram-bot optionnel a échoué"

echo "[+] Initialisation des dossiers"
mkdir -p recon rapport findings/_candidates state js

if [ ! -f scope.txt ]; then
    cp scope.txt.example scope.txt
    echo "[!] scope.txt créé depuis scope.txt.example. Édite-le avant de lancer."
fi

if [ ! -f .web_token ]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > .web_token
    chmod 600 .web_token
fi
WEB_TOKEN=$(cat .web_token)

cat <<INSTRUCTIONS

╔══════════════════════════════════════════════════════════════════════╗
║  Installation terminée.                                              ║
╠══════════════════════════════════════════════════════════════════════╣

Configuration restante :

  1. Pose ta clé Anthropic :
       export ANTHROPIC_API_KEY=sk-ant-...
     (ou ajoute la ligne à ~/.bashrc pour la persister)

  2. Édite scope.txt avec tes domaines autorisés :
       nano scope.txt

Trois façons de lancer :

  A. Web UI mobile (recommandé) :
       export BUGBOUNTY_WEB_TOKEN=$WEB_TOKEN
       python3 webapp.py --host 0.0.0.0 --port 8080
     Ouvre dans Chrome :
       http://localhost:8080/?token=$WEB_TOKEN

  B. Bot Telegram (remote control) :
       export TELEGRAM_BOT_TOKEN=...        (créé via @BotFather)
       export TELEGRAM_ALLOWED_CHATS=<ton-chat-id>
       python3 bot.py

  C. CLI directe (Termux session) :
       python3 autopilot.py --target example.com

Pour le bot Telegram, garde Termux en background :
       termux-wake-lock
       nohup python3 bot.py > bot.log 2>&1 &

╚══════════════════════════════════════════════════════════════════════╝

INSTRUCTIONS
