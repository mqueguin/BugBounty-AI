#!/usr/bin/env bash
# Executé automatiquement par GitHub Codespaces après la création du container.
# Installe toutes les dépendances pour BugBounty-AI.

set -e

echo "[+] Installation des deps Python"
pip install --upgrade pip
pip install -r requirements.txt
pip install "python-telegram-bot[job-queue]>=21.0" || echo "  (bot optionnel)"

echo "[+] Installation des outils recon Go"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%@*}")
    echo "  - $name"
    go install "$tool" 2>&1 | tail -3 || echo "    (échec non-bloquant)"
done

echo "[+] Installation paramspider"
if [ ! -d "$HOME/ParamSpider" ]; then
    git clone --quiet https://github.com/devanshbatham/ParamSpider.git "$HOME/ParamSpider"
    pip install -q -r "$HOME/ParamSpider/requirements.txt" || true
    sudo tee /usr/local/bin/paramspider > /dev/null <<'EOF'
#!/usr/bin/env bash
python3 "$HOME/ParamSpider/paramspider.py" "$@"
EOF
    sudo chmod +x /usr/local/bin/paramspider
fi

echo "[+] Préparation des dossiers"
mkdir -p recon rapport findings/_candidates state js

if [ ! -f scope.txt ]; then
    cp scope.txt.example scope.txt
fi

# Ajoute go path au shell de façon persistante
if ! grep -q "GOPATH" "$HOME/.bashrc" 2>/dev/null; then
    cat >> "$HOME/.bashrc" <<'EOF'

# BugBounty-AI
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
EOF
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  BugBounty-AI prêt.                                       ║"
echo "║  Prochaine étape : ouvre IPHONE.md et suis le guide.      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
