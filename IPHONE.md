# BugBounty-AI sur iPhone avec ton abonnement Claude Max

Tu as **Claude Max** à ~100€/mois. Tu ne veux **pas** payer l'API en plus. C'est l'usage supporté ici — on utilise ton abo via un **OAuth token** qui remplace la clé API.

**Principe** : Claude Code (la CLI d'Anthropic) sait s'authentifier avec ton abonnement via un token long-vécu (`CLAUDE_CODE_OAUTH_TOKEN`). L'autopilot l'utilise via `claude -p`. Résultat : **0€ d'API**, consommation contre ton quota Max.

---

## Ce que tu vas obtenir

- Une **web app mobile** accessible dans Safari, déployée sur Railway (~5€/mo pour le serveur)
- Autopilot entièrement piloté par Claude (via ton abo Max, aucun coût API)
- Optionnel : bot Telegram pour notifs push
- **Total récurrent** : ~5€/mo Railway + 0€ API = **≤5€/mo en plus de ton Max**

---

## Vue d'ensemble

Tu as trois étapes :

1. **Générer le token OAuth** une seule fois (`claude setup-token`)
2. **Déployer sur Railway** en 1-click depuis Safari
3. **Coller le token** dans Railway → usage illimité

Le token dure 1 an. Tu le regénères 1 fois par an.

---

## Étape 1 — Générer `CLAUDE_CODE_OAUTH_TOKEN`

C'est l'étape qui demande **un accès ponctuel à un terminal** (une fois dans l'année). Trois options, par ordre de simplicité :

### Option A — Sur un Mac/PC/Linux que tu peux emprunter (5 min)

```bash
# 1. Installe Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# 2. Génère le token — ouvre un navigateur pour le login Max
claude setup-token
```

Le CLI imprime un token qui commence par `sk-ant-oat01-...`. **Copie-le.**

### Option B — Depuis ton iPhone via Railway (10 min, 0 PC nécessaire)

Après avoir déployé sur Railway (étape 2), utilise le terminal web de Railway :

1. Dashboard Railway → ton service → menu **⋯** → **Shell** (terminal web, accessible dans Safari)
2. Dans ce terminal : tape `claude setup-token`
3. Le CLI affiche une URL `https://claude.ai/oauth/authorize?...`
4. **Tape longuement sur l'URL** dans Safari → *Copier* → colle dans un nouvel onglet Safari
5. Connecte-toi avec ton compte Max, autorise
6. Safari te redirige vers une page avec un code à copier (ou Safari te montre une erreur avec le code dans l'URL)
7. Colle le code dans le shell Railway → token généré, s'affiche
8. Copie le token

### Option C — Via GitHub Codespaces (10 min)

1. Safari → [github.com/codespaces](https://github.com/codespaces) → lance un codespace sur ton fork BugBounty-AI
2. Dans le terminal du codespace : `curl -fsSL https://claude.ai/install.sh | bash && ~/.local/bin/claude setup-token`
3. Suis l'OAuth en Safari
4. Copie le token affiché

---

## Étape 2 — Déploie sur Railway

Si c'est pas encore fait :

1. **Fork** : Safari → [github.com/byAz1nee/BugBounty-AI](https://github.com/byAz1nee/BugBounty-AI) → **Fork**
2. **Déploie** : Safari → [railway.com](https://railway.com) → **Login with GitHub** → **+ New Project** → **Deploy from GitHub repo** → ton fork
3. Railway détecte le Dockerfile et build (~5 min pendant que tu prépares les variables)

**Variables à ajouter** (onglet *Variables* du service) :

| Name | Value | Notes |
|------|-------|-------|
| `CLAUDE_CODE_OAUTH_TOKEN` | `sk-ant-oat01-...` | **⭐ celui de l'étape 1** |
| `BUGBOUNTY_WEB_TOKEN` | 24 caractères aléatoires (ex. `J8f3kL9mN2pQ7rT4uY6wX1zA`) | auth de la web UI |

**⚠ Ne mets PAS `ANTHROPIC_API_KEY`** — si elle est là, Claude Code l'utilise à la place du token subscription (et tu paies l'API).

**Networking** (Settings) → **Generate Domain** → URL HTTPS du type `bugbounty-ai-production.up.railway.app`.

**Volume** (Settings) → **+ New Volume** → Mount Path `/app/findings`, Size `1 GB`. Les findings survivront aux redémarrages.

---

## Étape 3 — Vérifie & bosse

Ouvre dans Safari :

```
https://<ton-domaine-railway>/?token=<TON-BUGBOUNTY-WEB-TOKEN>
```

Tu devrais voir un bandeau :

> ✅ **Claude Max subscription** active (via `CLAUDE_CODE_OAUTH_TOKEN`) — les scans autopilot utilisent ton abonnement, pas l'API.

Si tu vois plutôt 💳 *API key active* : tu as laissé `ANTHROPIC_API_KEY` dans les variables. Supprime-la et redémarre le service.

**Ajoute à l'écran d'accueil** : menu partage Safari → *Sur l'écran d'accueil*.

---

## Lance ta première chasse

Dans l'app :
1. Tape ton domaine autorisé → **Ajouter au scope**
2. Mode : **Autopilot** → **Démarrer**
3. Ferme l'app. Claude (via ton abo Max) fait la chasse.
4. Reviens voir les findings dans l'onglet **Findings**.

---

## Bonus — Telegram pour les notifs push

Sans ça, tu dois ouvrir Safari régulièrement. Avec ça, ton iPhone vibre à la fin du scan.

### Crée un bot
Telegram app → cherche **@BotFather** → `/newbot` → nomme-le → **token**.

### Trouve ton `chat_id`
1. Ouvre ton bot dans Telegram → `/start`
2. Safari → `https://api.telegram.org/bot<TON-TOKEN>/getUpdates` → trouve `"chat":{"id":XXXX`

### Configure
Railway → Variables :
- `TELEGRAM_BOT_TOKEN` = le token BotFather
- `TELEGRAM_ALLOWED_CHATS` = ton chat_id

### Démarre un 2e service
Railway → ton projet → **+ Create** → **Empty Service** → renomme `bot` :
- **Settings → Source** → Connect le même repo
- **Settings → Deploy → Custom Start Command** : `python3 bot.py`
- **Variables** → partage les 3 vars précédentes (`CLAUDE_CODE_OAUTH_TOKEN`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_CHATS`) via **Shared Variables**

Depuis Telegram sur ton iPhone :

```
/scan example.com          → lance autopilot
/status                     → état
/findings                   → liste
/finding <slug>             → détail
```

---

## Qui pilote ? Vraiment ?

**Claude (moi) via `claude -p` en mode headless**, authentifié par ton OAuth token Max.

`autopilot_max.py` :

```python
cmd = [
    "claude", "-p",
    "--dangerously-skip-permissions",
    "--output-format", "stream-json",
    prompt,  # "Fais recon + tri + probes XSS + findings sur <target>"
]
env["CLAUDE_CODE_OAUTH_TOKEN"] = ...  # ton abo
subprocess.Popen(cmd, env=env)
```

Côté Claude Code (moi) dans le container Railway : j'ai accès à `.claude/agents/`, `.claude/skills/`, `.claude/commands/` → je peux déléguer à `recon-specialist`, `vuln-hunter`, appliquer les méthodo XSS/SQLi/IDOR/SSRF/JWT, écrire les findings, etc.

Les **garde-fous** s'appliquent toujours :
- Scope vérifié contre `scope.txt` avant tout lancement
- Prompt autopilot impose "pas de test destructif, curl GET-only, 10 probes XSS max"
- Volume Railway garde tes findings

---

## Coût récapitulatif

| Item | Coût |
|------|------|
| Claude Max (déjà chez toi) | ~100€/mo |
| Railway Hobby (serveur) | **~5€/mo** |
| API Anthropic | **0€** (tu utilises le Max) |
| Domaine Railway | gratuit (`*.up.railway.app`) |
| **Total supplémentaire** | **~5€/mo** |

Pour comparaison avec l'API : un autopilot complet peut coûter 0.50 à 5€ de tokens avec `claude-opus-4-7`. Sur 20 scans/mois c'est 10-100€. **Le token OAuth t'épargne ça.**

---

## Limites à savoir

- **Quota Max** : l'abonnement a des limites de requêtes/messages par 5h. Si tu lances beaucoup de scans d'affilée, tu peux atteindre la limite (le scan se mettra en pause temporairement).
- **Durée du token** : 1 an. Garde un calendrier pour le regénérer.
- **Rate limit Anthropic** : si tu exécutes des scans en parallèle, Claude Code peut temporiser. Un scan à la fois = pas de problème.

---

## Problèmes fréquents

| Symptôme | Fix |
|----------|-----|
| Bandeau web UI = `❌ Aucune auth` | Oublié de poser `CLAUDE_CODE_OAUTH_TOKEN` dans Railway. Ajoute-le et redémarre. |
| Bandeau = `💳 API key active` alors que tu veux le Max | Supprime `ANTHROPIC_API_KEY` des vars Railway. |
| `claude: command not found` dans les logs | Le build Docker a échoué à installer Claude Code. Redéploie (parfois transient). |
| `Authentication error` | Token OAuth expiré (1 an) ou révoqué. Regénère-en un. |
| Le scan reste en `running` des heures | Railway l'a peut-être killé. Restart le service et relance. |
| `Findings` vide alors que le scan a tourné | Regarde `state/claude_max.log` (bouton *Logs* en haut) pour voir où ça bloque. |

---

## Si tu veux tester sans encore déployer sur Railway

Si tu as un Mac/PC à portée :

```bash
git clone https://github.com/<ton-pseudo>/BugBounty-AI
cd BugBounty-AI
pip install -r requirements.txt
curl -fsSL https://claude.ai/install.sh | bash       # installe Claude Code
claude setup-token                                    # génère le token (Safari OAuth)
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
echo "example.com" > scope.txt
python3 autopilot_max.py --target example.com
```

Ça utilise ton abo Max, aucun coût API.

Ensuite tu déploies sur Railway pour pouvoir piloter depuis l'iPhone en permanence.
