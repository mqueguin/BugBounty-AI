"""
Autopilot — boucle agentique Claude pour bug bounty.

Claude orchestre lui-même la chasse via tool use :
- run_command (recon)
- read_file / write_file
- probe_xss_reflected (probe non-destructive)
- write_finding (persiste un finding)
- finish (termine la boucle)

Usage : depuis IABounty.py via --autopilot, ou directement :
    from autopilot import run_autopilot
    run_autopilot("example.com")
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import anthropic
import requests

DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-7")
HEADERS = {"User-Agent": "Mozilla/5.0 BugBountyBot"}
MAX_OUTPUT_BYTES = 8 * 1024
MAX_FILE_BYTES = 16 * 1024
MAX_ITERATIONS = 40

ALLOWED_BIN = {
    "subfinder", "assetfinder", "amass", "httpx", "httpx-toolkit",
    "gau", "waybackurls", "paramspider", "katana", "gf", "jq",
    "curl", "dig", "host", "whois", "nslookup",
    "sort", "uniq", "wc", "head", "tail", "grep", "cat", "ls",
    "mkdir", "echo", "tr", "cut", "awk", "sed",
}

DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\s+/",
    r"\bdrop\s+table\b",
    r":\(\)\{",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bsudo\b",
    r">\s*/dev/sda",
    r"\bcurl\s+.+\|\s*sh",
    r"\bwget\s+.+\|\s*sh",
]


SYSTEM_PROMPT = """Tu es un agent autonome de bug bounty. Tu opères dans un workspace Linux où tu disposes de tools pour reconnaître une cible, analyser des endpoints, et persister des findings.

## Contraintes éthiques NON-NÉGOCIABLES

- Tu ne testes QUE les domaines explicitement passés en paramètre (déjà vérifiés contre scope.txt par le harness).
- Tu n'exécutes JAMAIS de payload destructif (DROP, DELETE, brute-force, DoS, exfiltration massive).
- Tu utilises UNIQUEMENT les outils whitelistés : subfinder, httpx, gau, waybackurls, paramspider, katana, gf, jq, curl (GET/HEAD), dig, sort, uniq, etc.
- Pour tester une XSS reflected, tu utilises EXCLUSIVEMENT le tool `probe_xss_reflected` (marqueur inoffensif `xssTEST1234`).
- Limite : max 10 requêtes actives (probe_xss_reflected) par run.
- Si tu n'es pas sûr → arrête, écris ton hypothèse en finding `_candidate_*.md`, et passe à autre chose.

## Workflow attendu

1. **Recon passive** : subfinder → httpx → gau → paramspider → katana. Output dans `recon/`.
2. **Lis** les fichiers pour repérer les endpoints intéressants (params, /api/, /admin, /upload, /redirect, .git, .env, swagger, actuator).
3. **Priorise** les top 10-15 endpoints (paramètres dynamiques, technos exotiques, status auth).
4. **Pour chaque candidat XSS** (URL avec query string) → `probe_xss_reflected` → si reflected, `write_finding` avec slug, sévérité Medium/High, et PoC.
5. **Pour les autres catégories** (SQLi/IDOR/SSRF/JWT) : tu ne testes pas activement, tu écris des findings `_candidate_*.md` documentant la surface d'attaque et l'attaque manuelle suggérée.
6. **À la fin**, appelle `finish` avec un résumé de ce que tu as fait.

## Règles de format finding

- slug = `<vuln-type>-<asset>-<short-desc>` (kebab-case, < 60 chars)
- vuln_type : XSS, SQLi, IDOR, SSRF, JWT, Open-Redirect, Path-Traversal, etc.
- Severity : Critical | High | Medium | Low | Info
- Si non confirmé, ajoute `[CANDIDATE]` au début du title

## Économise les tokens

- Ne re-lis pas un fichier déjà lu.
- Ne re-lance pas une commande déjà exécutée.
- Quand tu as un signal clair, écris le finding et passe à autre chose.
- Si après 3 itérations sans nouveau signal, appelle `finish`.

Tu as max %d itérations. Sois efficace.""" % MAX_ITERATIONS


TOOLS = [
    {
        "name": "run_command",
        "description": (
            "Exécute une commande shell de reconnaissance. "
            "Outils autorisés : subfinder, httpx, gau, waybackurls, paramspider, katana, "
            "gf, jq, curl (GET/HEAD seulement), dig, sort, uniq, head, tail, grep, cat, ls, mkdir. "
            "Pas de pipe vers sh, pas de sudo, pas de rm -rf. "
            "Output capturé et tronqué à 8 KB."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Commande shell"},
                "timeout_sec": {"type": "integer", "description": "Timeout en secondes (max 180)", "default": 60},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Lit un fichier du workspace (texte). Tronqué à 16 KB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Chemin relatif au workspace"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Écrit un fichier dans le workspace (crée les dossiers parents). Pas de chemins absolus, pas de remontée hors workspace.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "probe_xss_reflected",
        "description": (
            "Test XSS non-destructif : injecte le marqueur 'xssTEST1234' dans chaque paramètre "
            "GET de l'URL et vérifie s'il est reflété dans la réponse. Aucun JS exécuté. "
            "Retourne {reflected: bool, params: [param_name, ...], status: int}."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL avec query string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "write_finding",
        "description": "Persiste un finding bug bounty au format Markdown standard.",
        "input_schema": {
            "type": "object",
            "properties": {
                "slug": {"type": "string", "description": "kebab-case, < 60 chars"},
                "title": {"type": "string"},
                "vuln_type": {"type": "string"},
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                "url": {"type": "string"},
                "summary": {"type": "string"},
                "reproduction": {"type": "string", "description": "Étapes numérotées"},
                "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "confirmed": {"type": "boolean", "description": "false = candidat à valider manuellement"},
            },
            "required": ["slug", "title", "vuln_type", "severity", "url", "summary", "reproduction", "impact", "remediation", "confirmed"],
        },
    },
    {
        "name": "finish",
        "description": "Termine le run autopilot. À appeler quand tu as fini ou si tu n'as plus rien à faire.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Résumé en 3-5 phrases"},
            },
            "required": ["summary"],
        },
    },
]


def _safe_path(workspace: Path, path: str) -> Path:
    candidate = (workspace / path).resolve()
    if not str(candidate).startswith(str(workspace.resolve())):
        raise ValueError(f"Chemin hors workspace : {path}")
    return candidate


def _is_command_safe(command: str) -> tuple[bool, str]:
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Pattern destructif refusé : {pattern}"
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return False, f"Commande mal formée : {exc}"
    if not tokens:
        return False, "Commande vide"
    binaries_in_command = []
    for token in tokens:
        if token in ("|", "&&", "||", ";", ">", ">>", "<"):
            continue
        if "/" in token or token.startswith("-") or token.startswith("$") or "=" in token:
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", token):
            binaries_in_command.append(token)
    main_bin = binaries_in_command[0] if binaries_in_command else ""
    if main_bin and main_bin not in ALLOWED_BIN:
        return False, f"Binaire non whitelisté : {main_bin}"
    if "curl" in tokens:
        idx = tokens.index("curl")
        rest = tokens[idx + 1:]
        unsafe_flags = {"-X", "--request", "-d", "--data", "--data-binary", "-T", "--upload-file"}
        for i, t in enumerate(rest):
            if t in unsafe_flags:
                if t in ("-X", "--request") and i + 1 < len(rest) and rest[i + 1].upper() not in ("GET", "HEAD"):
                    return False, f"curl méthode non-GET interdite : {rest[i+1]}"
                if t in ("-d", "--data", "--data-binary", "-T", "--upload-file"):
                    return False, "curl avec body interdit (read-only)"
    return True, ""


def _truncate(text: str, limit: int) -> str:
    if len(text.encode("utf-8")) <= limit:
        return text
    truncated = text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")
    return truncated + f"\n\n[... tronqué à {limit} bytes ...]"


def _execute_run_command(workspace: Path, command: str, timeout_sec: int) -> dict:
    ok, reason = _is_command_safe(command)
    if not ok:
        return {"error": reason}
    timeout_sec = max(5, min(int(timeout_sec or 60), 180))
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            cwd=str(workspace), timeout=timeout_sec,
        )
        return {
            "exit_code": result.returncode,
            "stdout": _truncate(result.stdout, MAX_OUTPUT_BYTES),
            "stderr": _truncate(result.stderr, MAX_OUTPUT_BYTES // 4),
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout après {timeout_sec}s"}
    except Exception as exc:
        return {"error": str(exc)}


def _execute_read_file(workspace: Path, path: str) -> dict:
    try:
        target = _safe_path(workspace, path)
        if not target.exists():
            return {"error": f"Fichier inexistant : {path}"}
        if target.is_dir():
            entries = sorted(p.name for p in target.iterdir())
            return {"directory": True, "entries": entries[:200]}
        content = target.read_text(errors="ignore")
        return {"content": _truncate(content, MAX_FILE_BYTES)}
    except Exception as exc:
        return {"error": str(exc)}


def _execute_write_file(workspace: Path, path: str, content: str) -> dict:
    try:
        target = _safe_path(workspace, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"written": str(target.relative_to(workspace)), "bytes": len(content)}
    except Exception as exc:
        return {"error": str(exc)}


def _execute_probe_xss(url: str, probe_count: list[int]) -> dict:
    if probe_count[0] >= 10:
        return {"error": "Quota probe_xss_reflected atteint (10/run)"}
    probe_count[0] += 1
    marker = "xssTEST1234"
    try:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        if not query:
            return {"reflected": False, "reason": "Pas de paramètres GET"}
        reflected_params = []
        last_status = None
        for param in query:
            new_query = {**query, param: marker}
            encoded = urlencode(new_query, doseq=True)
            test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, parsed.fragment))
            resp = requests.get(test_url, headers=HEADERS, timeout=10, allow_redirects=False)
            last_status = resp.status_code
            if marker in resp.text:
                reflected_params.append(param)
        return {
            "reflected": bool(reflected_params),
            "params": reflected_params,
            "status": last_status,
            "marker": marker,
        }
    except requests.RequestException as exc:
        return {"error": str(exc)}


def _execute_write_finding(workspace: Path, args: dict) -> dict:
    slug = re.sub(r"[^a-z0-9-]", "-", args["slug"].lower())[:60]
    confirmed = bool(args.get("confirmed", False))
    folder = workspace / "findings"
    if not confirmed:
        folder = folder / "_candidates"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{slug}.md"
    body = f"""# {args['title']}

- **Cible** : {args['url']}
- **Type** : {args['vuln_type']}
- **Sévérité estimée** : {args['severity']}
- **Confirmé** : {'Oui' if confirmed else 'NON — candidat à valider manuellement'}
- **Découvert le** : {datetime.utcnow().isoformat(timespec='seconds')}Z

## Résumé
{args['summary']}

## Reproduction
{args['reproduction']}

## Impact
{args['impact']}

## Remédiation suggérée
{args['remediation']}

## Notes
Généré automatiquement par autopilot. À relire avant soumission.
"""
    target.write_text(body, encoding="utf-8")
    return {"written": str(target.relative_to(workspace))}


def _state_path(workspace: Path) -> Path:
    return workspace / "state" / "current.json"


def _save_state(workspace: Path, state: dict) -> None:
    p = _state_path(workspace)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2))


def _append_log(workspace: Path, line: str) -> None:
    log = workspace / "state" / "autopilot.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"[{datetime.utcnow().isoformat(timespec='seconds')}Z] {line}\n")


def run_autopilot(target: str, workspace: Path | str = ".", model: str = DEFAULT_MODEL,
                  max_iterations: int = MAX_ITERATIONS, on_event=None) -> dict:
    """Lance la boucle autopilot. on_event(dict) est appelé à chaque tool call/result."""
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY non défini")

    client = anthropic.Anthropic()
    probe_count = [0]
    findings_written = []
    started_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    state = {
        "target": target,
        "status": "running",
        "started_at": started_at,
        "iterations": 0,
        "findings": [],
        "summary": "",
        "model": model,
    }
    _save_state(workspace, state)
    _append_log(workspace, f"Autopilot démarré sur {target} (modèle {model})")

    messages = [{
        "role": "user",
        "content": (
            f"Cible autorisée : `{target}`. Lance le workflow complet : recon, "
            "tri des endpoints intéressants, probe XSS sur les candidats, "
            "écriture des findings. Termine avec finish() quand tu as épuisé "
            "les pistes raisonnables (≤ %d itérations)." % max_iterations
        ),
    }]

    iteration = 0
    finished = False
    final_summary = ""

    while iteration < max_iterations and not finished:
        iteration += 1
        state["iterations"] = iteration
        _save_state(workspace, state)
        _append_log(workspace, f"Itération {iteration}")

        try:
            response = client.messages.create(
                model=model,
                max_tokens=8000,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
        except anthropic.APIError as exc:
            _append_log(workspace, f"API error: {exc}")
            state["status"] = "error"
            state["error"] = str(exc)
            _save_state(workspace, state)
            return state

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            text = next((b.text for b in response.content if b.type == "text"), "")
            final_summary = text or "Fin sans appel à finish()."
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            name, args = block.name, block.input
            _append_log(workspace, f"tool_use: {name} {json.dumps(args)[:200]}")
            if on_event:
                on_event({"type": "tool_use", "name": name, "input": args, "iteration": iteration})

            try:
                if name == "run_command":
                    result = _execute_run_command(workspace, args["command"], args.get("timeout_sec", 60))
                elif name == "read_file":
                    result = _execute_read_file(workspace, args["path"])
                elif name == "write_file":
                    result = _execute_write_file(workspace, args["path"], args["content"])
                elif name == "probe_xss_reflected":
                    result = _execute_probe_xss(args["url"], probe_count)
                elif name == "write_finding":
                    result = _execute_write_finding(workspace, args)
                    if "written" in result:
                        findings_written.append(result["written"])
                        state["findings"] = findings_written
                        _save_state(workspace, state)
                elif name == "finish":
                    finished = True
                    final_summary = args.get("summary", "")
                    result = {"acknowledged": True}
                else:
                    result = {"error": f"Tool inconnu : {name}"}
            except Exception as exc:
                result = {"error": str(exc)}

            if on_event:
                on_event({"type": "tool_result", "name": name, "result": result, "iteration": iteration})

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(result)[:6000],
            })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    state["status"] = "done" if finished else "max_iterations"
    state["summary"] = final_summary
    state["finished_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    state["probe_count"] = probe_count[0]
    _save_state(workspace, state)
    _append_log(workspace, f"Fin (iterations={iteration}, findings={len(findings_written)}, probes={probe_count[0]})")
    return state


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Autopilot bug bounty (Claude tool use)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS)
    args = parser.parse_args()
    final_state = run_autopilot(args.target, args.workspace, args.model, args.max_iterations)
    print(json.dumps(final_state, indent=2))
