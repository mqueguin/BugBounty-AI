# BugBounty-AI sur iPhone — setup sans terminal

**Tu n'as que ton iPhone.** Tu ne veux pas taper dans un terminal. Tu acceptes de payer ~5€/mois.

On déploie l'app sur **Railway** (plateforme cloud). Tu fais **tout dans Safari**, en tapant dans des formulaires. Ensuite tu bosses depuis :

- **Safari** (web UI mobile-first) — pour lancer des scans et lire les findings
- **Telegram** (optionnel) — notifications push et contrôle par commandes

**Temps : 10 min. Coût : ~5€/mois** (crédits Railway ; la première fois tu as 5$ offerts).

---

## Étape 1 — Récupère ta clé API Anthropic

Dans Safari, va sur [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) :

1. Sign in (compte Anthropic requis, gratuit)
2. **Create Key** → nomme-la `bugbounty` → **Create**
3. **Copie la clé** (elle commence par `sk-ant-`). Tu ne pourras plus la voir après.

Mets-la de côté dans l'app Notes de ton iPhone.

---

## Étape 2 — Fork le dépôt sur GitHub

1. Va sur [github.com/byAz1nee/BugBounty-AI](https://github.com/byAz1nee/BugBounty-AI)
2. Sign in (compte GitHub requis, gratuit)
3. Tape **Fork** (coin haut droit) → **Create fork**
4. Tu as maintenant ton propre fork, par exemple `github.com/<ton-pseudo>/BugBounty-AI`

---

## Étape 3 — Déploie sur Railway

1. Va sur [railway.com](https://railway.com) dans Safari
2. **Login with GitHub** (autorise Railway à lire ton fork)
3. Sur le dashboard : **+ New Project** → **Deploy from GitHub repo**
4. Sélectionne ton fork **BugBounty-AI**
5. Railway détecte automatiquement le `Dockerfile` et commence le build

Pendant le build (~5 min) :

6. Tape sur le service *BugBounty-AI* dans le projet → onglet **Variables** → **+ New Variable**
7. Ajoute ces 3 variables une par une :

   | Name | Value |
   |------|-------|
   | `ANTHROPIC_API_KEY` | colle ta clé `sk-ant-...` |
   | `BUGBOUNTY_WEB_TOKEN` | génère 24 chars aléatoires (ex : `J8f3kL9mN2pQ7rT4uY6wX1zA`) |
   | `ANTHROPIC_MODEL` | `claude-opus-4-7` |

8. Onglet **Settings** → section **Networking** → **Generate Domain** → Railway te donne une URL du type `bugbounty-ai-production.up.railway.app`
9. Onglet **Settings** → section **Volumes** → **+ New Volume** :
   - Mount Path : `/app/findings`
   - Size : 1 GB
   *(pour que tes findings survivent aux redémarrages)*

Une fois le build fini (tu vois **Active** en vert), l'URL est opérationnelle.

---

## Étape 4 — Ouvre l'app dans Safari

Ouvre dans Safari :

```
https://<ton-domaine-railway>/?token=<TON-BUGBOUNTY-WEB-TOKEN>
```

Exemple :
```
https://bugbounty-ai-production.up.railway.app/?token=J8f3kL9mN2pQ7rT4uY6wX1zA
```

Tu vois le **dashboard noir mobile-first**.

> 💡 **Ajoute à l'écran d'accueil** : menu partage Safari → *Sur l'écran d'accueil*. Tu auras une icône comme une app native.

---

## Étape 5 — Lance ta première chasse

Dans le dashboard :

1. **Scope vide** → dans le champ, tape ton domaine autorisé (programme HackerOne/Bugcrowd officiel) → **Ajouter au scope**
2. **Lancer un scan** :
   - Cible : ton domaine
   - Mode : **Autopilot (Claude orchestre tout)**
   - **Démarrer**
3. La page **Status** s'affiche (refresh auto toutes les 5s)
4. Les findings apparaissent dans l'onglet **Findings** au fur et à mesure

**Tu peux fermer Safari.** Le scan continue côté Railway. Reviens quand tu veux.

---

## Bonus — Notifications Telegram sur ton iPhone

Pour recevoir une notification push quand un scan se termine (et contrôler par commandes) :

### Crée un bot Telegram

Dans l'app Telegram sur ton iPhone :

1. Cherche **@BotFather** → lance-le → `/newbot`
2. Donne un nom, puis un username (finit par `bot`)
3. BotFather te donne un **token** (format `123456:ABC-DEF...`). Copie-le.

### Trouve ton chat_id

1. Cherche ton nouveau bot dans Telegram → `/start`
2. Dans Safari, ouvre : `https://api.telegram.org/bot<TON-TOKEN>/getUpdates`
3. Cherche `"chat":{"id":123456789` → **c'est ton chat_id**

### Ajoute les variables sur Railway

Retourne sur Railway → ton service → **Variables** → ajoute :

| Name | Value |
|------|-------|
| `TELEGRAM_BOT_TOKEN` | le token BotFather |
| `TELEGRAM_ALLOWED_CHATS` | ton chat_id (juste le nombre) |

**Attention** : Railway va redémarrer ton service automatiquement.

### Démarre le bot

Actuellement, le service Railway ne lance que le webapp. Pour ajouter le bot Telegram :

1. Sur Railway, dans ton projet → **+ Create** → **Empty Service** → renomme-le `bot`
2. **Settings** → **Source** → **Connect Repo** → ton fork BugBounty-AI
3. **Settings** → **Deploy** → **Custom Start Command** :
   ```
   python3 bot.py
   ```
4. **Variables** → **Add reference** → copie les 3 mêmes variables du premier service
5. Deploy → tu peux maintenant envoyer `/scan example.com` depuis Telegram

---

## Utilisation quotidienne

### Depuis Safari
1. Ouvre ton raccourci iPhone
2. Tape **Démarrer** avec ta cible
3. Fais autre chose
4. Reviens plus tard voir les findings

### Depuis Telegram
```
/scan example.com          → autopilot
/status                     → où on en est
/findings                   → liste
/finding xss-exemple-slug   → contenu complet du finding
/cancel                     → stop le scan
```

---

## Qui pilote l'attaque ?

**Claude (moi, `claude-opus-4-7` via l'API Anthropic).**

Dans `autopilot.py`, il y a une boucle :

```
tant que pas fini :
    réponse = claude.envoie(tools=[run_command, probe_xss, write_finding, ...])
    pour chaque action_demandée par Claude :
        exécute-la (avec garde-fous)
        renvoie le résultat à Claude
    si Claude dit "finish" : stop
```

Claude choisit :
- Quels outils lancer (`subfinder`, `httpx`, `gau`, etc.) et avec quels flags
- Quels endpoints sont prometteurs
- Quels paramètres GET tester en XSS
- Quand écrire un finding (et quoi mettre dedans)
- Quand s'arrêter

Le Python ne fait que **exécuter** et **refuser ce qui est dangereux** (rm -rf, DROP TABLE, curl POST, sudo…).

---

## Coût

Railway facture à l'usage. Pour un scanner qui tourne épisodiquement :

- **Hobby plan** : 5$/mois inclus (crédit)
- Web service + volume 1 GB : **~3-5$/mois** en usage typique
- Tu es alerté bien avant de dépasser ton crédit

Les **tokens Claude** sont facturés séparément sur ton compte Anthropic. Comptes :

- **Autopilot par domaine** : ~0.50€ à 2€ selon la taille de la recon (avec `claude-opus-4-7`)
- Si tu veux réduire → mets `ANTHROPIC_MODEL=claude-sonnet-4-6` dans Railway (~3x moins cher)

---

## Problèmes fréquents

| Symptôme | Solution |
|----------|----------|
| Page Railway 502 | Build pas fini, attends 2 min |
| `Token invalide` dans Safari | Vérifie que `?token=...` match ton `BUGBOUNTY_WEB_TOKEN` |
| Scan reste en *running* pendant des heures | Railway l'a peut-être killé (mémoire). `Restart` le service, relance. |
| Findings perdus après redémarrage | Tu as oublié le volume sur `/app/findings` (étape 3, point 9) |
| Claude refuse de tester | Ta cible n'est pas dans `scope.txt`. Ajoute-la depuis le dashboard. |

---

## Alternatives si Railway ne te convient pas

- **Render.com** : même principe, utilise `render.yaml` fourni dans le repo. Gratuit si tu acceptes que le service dorme après 15 min d'inactivité.
- **Fly.io** : `fly launch --dockerfile` depuis un terminal. Gratuit généreux.
- **GitHub Codespaces** : voir `IPHONE.md` dans les anciennes versions (terminal nécessaire — pas top sur iPhone).
- **Raspberry Pi chez toi** + `docker run` : une fois par un pote, puis iPhone seul pour toujours.
