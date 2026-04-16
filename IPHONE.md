# BugBounty-AI sur iPhone — guide pas à pas

Tu n'as que ton iPhone. OK. On utilise **GitHub Codespaces** : un Linux qui tourne sur les serveurs de GitHub, pilotable depuis Safari, gratuit 60h/mois. Tout se fait dans le navigateur.

Temps total : **~5 minutes**.

---

## Étape 0 — Pré-requis

Tu as besoin de :

1. **Un compte GitHub** (gratuit) — [github.com/signup](https://github.com/signup)
2. **Une clé API Anthropic** — [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) → *Create Key* → copie (commence par `sk-ant-`)
3. **Un domaine que tu as le droit de tester** (programme HackerOne/Bugcrowd/Intigriti officiel)

---

## Étape 1 — Fork du dépôt

1. Ouvre **Safari**, va sur : `https://github.com/byAz1nee/BugBounty-AI`
2. Tape **Fork** (icône en haut à droite), puis **Create fork**
3. Tu es maintenant sur `https://github.com/<ton-pseudo>/BugBounty-AI`

---

## Étape 2 — Lance un Codespace

1. Sur ton fork, tape le bouton vert **`<> Code`**
2. Onglet **Codespaces** → **Create codespace on main** (ou sur la branche `claude/bug-bounty-bot-1QdiX` si c'est celle que tu veux tester)
3. Safari ouvre un **VS Code web**. Attends ~2 min : l'installation auto des outils (subfinder, httpx, etc.) tourne en fond.
4. Quand tu vois `BugBounty-AI prêt` dans le terminal → c'est bon.

> Si le terminal n'est pas visible : menu **☰** en haut à gauche → **Terminal** → **New Terminal**.

---

## Étape 3 — Pose ta clé API

Dans le terminal du Codespace (en bas de l'écran), tape :

```bash
export ANTHROPIC_API_KEY=sk-ant-...ta-clé...
```

**Astuce iPhone** : pour coller, appuie longuement dans le terminal → *Coller*.

Pour éviter de la retaper à chaque session, rends-la permanente :

1. Dans Safari, va sur ton fork GitHub → **Settings** (de ton profil, pas du repo) → **Codespaces** → **Repository secrets**
2. **New secret** : nom `ANTHROPIC_API_KEY`, valeur `sk-ant-...`
3. Elle sera injectée automatiquement au prochain codespace.

---

## Étape 4 — Démarre la web UI

Toujours dans le terminal :

```bash
bash quickstart.sh
```

Le script :
- Génère un token d'auth
- Lance `webapp.py` sur le port 8080
- T'affiche un lien du type :
  ```
  https://<ton-codespace>-8080.app.github.dev/?token=abc123...
  ```

---

## Étape 5 — Ouvre l'UI dans Safari

**Tape longuement sur l'URL** affichée dans le terminal → **Ouvrir un lien** → ça ouvre un nouvel onglet Safari. Tu vois un dashboard sombre mobile-first.

Si Safari te demande une authentification GitHub, c'est normal : les ports Codespaces sont privés par défaut, tu es déjà loggé donc ça passe.

---

## Étape 6 — Lance ta première chasse

Dans la web UI :

1. **Ajoute un domaine au scope** (en haut) : saisis `example.com` et tape *Ajouter au scope*.
2. **Démarre un scan** :
   - Cible : `example.com`
   - Mode : **Autopilot (Claude orchestre tout)**
   - Tape **Démarrer**
3. Tu es redirigé vers la page **Status** — rafraîchissement auto toutes les 5s.
4. Les findings apparaissent dans l'onglet **Findings** au fur et à mesure.

---

## Qui pilote l'attaque ?

**Claude (moi, `claude-opus-4-7` via l'API Anthropic).**

Concrètement, dans le code (`autopilot.py`) :

```
boucle:
    réponse = claude.messages.create(tools=[...], messages=[...])
    pour chaque tool_use dans réponse:
        execute(tool_use)        # run_command, probe_xss, write_finding...
        renvoie le résultat à Claude
    si Claude appelle finish() : stop
```

Claude décide :
- Quelle commande recon lancer et avec quels flags
- Quels endpoints sont prometteurs
- Quels paramètres GET probe pour XSS
- Quand écrire un finding (et quoi dedans)
- Quand s'arrêter

Le Python ne fait que :
- **Exécuter** ce que Claude demande
- **Refuser** ce qui est dangereux (rm -rf, DROP TABLE, curl POST, sudo, etc.)
- **Limiter** (10 probes XSS max, 40 itérations max)
- **Persister** l'état pour que tu puisses suivre depuis Safari

---

## Après le scan

- **Consulter un finding** : onglet *Findings* → tape sur un nom → le contenu Markdown s'affiche, bouton *Télécharger .md*.
- **Les findings `_candidates`** sont des hypothèses à valider manuellement (Claude n'a pas pu confirmer tout seul).
- **Copier un finding** : tape longuement sur le `pre` → *Tout sélectionner* → *Copier*.

---

## Pour le revenir demain

1. Va sur [github.com/codespaces](https://github.com/codespaces) dans Safari
2. Tape sur ton codespace (il est suspendu, pas supprimé)
3. Re-tape : `bash quickstart.sh` → l'URL repasse en vert.

> ⚠  Les Codespaces suspendus s'auto-suppriment après 30 jours d'inactivité. Tes findings persistent dans le codespace ; pour les sauvegarder : `git add findings && git commit -m "findings" && git push`.

---

## Alternative 100% iPhone : Telegram bot

Si tu préfères piloter depuis l'app **Telegram** (notifications push, pas besoin de garder Safari ouvert) :

1. Dans Telegram, parle à [@BotFather](https://t.me/BotFather) → `/newbot` → récupère le token
2. Récupère ton `chat_id` : envoie `/start` à ton nouveau bot, puis ouvre `https://api.telegram.org/bot<TOKEN>/getUpdates` dans Safari
3. Dans le terminal Codespace :
   ```bash
   export TELEGRAM_BOT_TOKEN=...
   export TELEGRAM_ALLOWED_CHATS=<ton-chat-id>
   nohup python3 bot.py > state/bot.log 2>&1 &
   ```
4. Dans Telegram : `/scan example.com`, `/status`, `/findings`, `/finding <slug>`.

---

## Limites connues depuis iPhone

- **Clavier** : le terminal VS Code est utilisable mais pas optimal sur iPhone. Les raccourcis iOS aident (`Cmd+V` si clavier Bluetooth).
- **60h gratuites/mois** sur Codespaces (largement suffisant pour du bug bounty).
- **Le codespace s'arrête** après 30 min d'inactivité par défaut. `bash quickstart.sh` le réveille.
- **HTTPS obligatoire** : les URLs `*.app.github.dev` sont en HTTPS, tout est chiffré.

---

## Si quelque chose casse

| Symptôme | Fix |
|----------|-----|
| `ANTHROPIC_API_KEY is not set` | Re-lance `export ANTHROPIC_API_KEY=...` ou configure le secret Codespaces |
| Port 8080 déjà utilisé | `pkill -f webapp.py` puis `bash quickstart.sh` |
| URL `app.github.dev` en 502 | Attends 10s (le Codespace se réveille) et recharge |
| `subfinder: command not found` | `bash .devcontainer/postCreate.sh` pour réinstaller |
| Findings vides alors que Claude a tourné | `cat state/autopilot.log` pour voir où ça a coincé |
