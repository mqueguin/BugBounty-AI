# Skill — IDOR (Insecure Direct Object Reference)

Manipulation de références directes à des objets pour accéder à des ressources d'autres users.

## 1. Identifier les candidats

Paramètres et chemins à haute probabilité IDOR :

- `/api/users/<id>`, `/user/<uuid>/profile`
- `?user_id=`, `?account=`, `?order=`, `?invoice=`
- `/documents/<id>/download`, `/tickets/<id>`
- Tokens dans URL (`?share=<b64>`)
- Session/cart IDs (`?cart=`, `?session=`)

## 2. Pré-requis : 2 comptes

Créer **2 comptes de test** (A et B) sur la plateforme. Logger les deux simultanément (Burp → sessions différentes ou curl avec cookies séparés).

## 3. Méthodologie

### Horizontal IDOR (user A → user B, même niveau)
1. Avec compte A, accède à ta ressource : `GET /api/users/12345`
2. Avec le cookie/token de A, tente la ressource de B : `GET /api/users/12346`
3. Si tu obtiens les données de B → IDOR confirmé.

### Vertical IDOR (user → admin)
1. Identifie un endpoint admin (ex: `/admin/users` ou `/api/admin/*`)
2. Avec cookie user standard, tente l'accès
3. Si la réponse contient des données admin → privilege escalation

## 4. Variantes d'ID

| ID format | Attaque |
|-----------|---------|
| Incrémental (`1, 2, 3`) | Simple itération |
| UUID v4 | Cherche leak dans logs/URLs/emails/headers |
| UUID v1 | Prédictible via timestamp + MAC (uuid-tool) |
| Hash MD5/SHA | Cherche la source : souvent email/username hashé |
| Base64 encoded | Décode, regarde structure interne |
| JWT | Vérifie signature, essaie de forger (voir `jwt-attacks.md`) |
| GraphQL node ID | Souvent `base64(Type:id)` → tripote le `id` |

## 5. Méthodes HTTP oubliées

Si `GET /api/users/12346` est bien protégé, essaie :

```
PUT /api/users/12346 {...}
DELETE /api/users/12346
PATCH /api/users/12346 {...}
POST /api/users/12346/avatar
```

Beaucoup d'apps ne vérifient l'ownership que sur GET.

## 6. Vecteurs alternatifs

- **Paramètre ajouté** : `/profile` → `/profile?user_id=<victim>`
- **Header custom** : `X-User-Id: <victim>`, `X-Forwarded-User`
- **JSON field swap** : `{"id": "<mine>", "owner": "<victim>"}`
- **Paramètre en double** : `?user_id=mine&user_id=victim` (HTTP parameter pollution)
- **Mass assignment** : POST body avec champs non-exposés (`"role": "admin"`)

## 7. Impact

| Scénario | Sévérité |
|----------|----------|
| Lecture metadata publique d'un autre user | Low/Info |
| Lecture PII (email, phone, address) | High |
| Lecture documents/paiements/messages | High/Critical |
| Modification/suppression ressource d'autrui | Critical |
| Privilege escalation → admin | Critical |

## 8. PoC — format

```http
# Request avec compte A, accédant à la ressource de B
GET /api/invoices/INV-00042 HTTP/1.1
Host: target.com
Cookie: session=<A_session>

# Response — contient les données de B
HTTP/1.1 200 OK
{"invoice":"INV-00042","user":"B@example.com","amount":"…"}
```

## 9. Règles éthiques

- **Lecture seule.** Ne modifie JAMAIS les ressources d'un autre user réel.
- **Ne dump pas** toute la base par itération. 2-3 IDs suffisent à prouver la faille.
- **Redact PII** des autres users dans le rapport (garde structure, masque valeurs : `user@e***.com`).
- Si tu tombes sur des données clairement sensibles (finances, santé) : **stoppe, rapporte, redact**.
