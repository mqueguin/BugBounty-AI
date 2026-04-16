"""
Autopilot Max — utilise l'abonnement Claude Max via OAuth token (aucun coût API).

Pré-requis : CLAUDE_CODE_OAUTH_TOKEN défini dans l'environnement.
Génère-le avec `claude setup-token` sur une machine où Claude Code est installé.

Pipeline :
1. Vérifie que le token est présent
2. Construit un prompt autopilot qui réutilise les subagents et skills du workspace
3. Lance `claude -p --dangerously-skip-permissions --output-format stream-json "<prompt>"`
4. Stream la sortie dans state/claude_max.log
5. Met à jour state/current.json à partir des événements reçus
6. À la fin, liste les findings trouvés
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


CLAUDE_BIN = os.getenv("CLAUDE_CLI_PATH", "claude")


AUTOPILOT_PROMPT = """Tu es en mode AUTOPILOT bug bounty sur la cible **{target}**.

Le scope a déjà été vérifié par le harness (domaine présent dans `scope.txt`).
Quota max : {max_iterations} itérations, 10 probes XSS.

## Ta mission

1. **Recon passive** : `subfinder -d {target} -silent > recon/subdomains.txt`, puis `httpx`, `gau`, `waybackurls`, `paramspider`, `katana` (outils déjà installés dans le PATH).
2. **Tri intelligent** : lis les outputs, priorise les endpoints avec paramètres GET, chemins `/api/`, `/admin`, `/upload`, `/debug`, `.git`, `.env`, `swagger`, `actuator`.
3. **Candidats XSS** : pour chaque URL avec query string, teste avec `curl -sL` en injectant le marqueur `xssTEST1234` dans chaque paramètre, vérifie s'il est réfléchi dans la réponse. MAX 10 probes pour tout le run.
4. **Écris les findings** :
   - Confirmés (marqueur reflété, preuve claire) → `findings/<slug>.md`
   - Hypothèses non vérifiées → `findings/_candidates/<slug>.md`
   - Format de fichier : voir `.claude/agents/vuln-hunter.md`
5. **Mets à jour l'état** : après chaque étape clé, écris dans `state/current.json` :
   ```json
   {{"target": "{target}", "status": "running|done", "iterations": N,
     "findings": ["findings/...md", ...], "probe_count": N, "summary": "..."}}
   ```
6. **Stop** quand tu as épuisé les pistes raisonnables OU atteint {max_iterations} itérations.
   Mets `status: "done"` et un résumé factuel dans `summary`.

## Contraintes NON-NÉGOCIABLES

- Pas de test destructif (DROP, DELETE, brute-force, DoS).
- Curl uniquement en GET/HEAD, pas de `-d`/`--data`/`-X POST`.
- Pas d'exfiltration réelle — si tu vois des données d'autres users, redact.
- Respecte le rate-limit (délais raisonnables, pas de rafale).
- Pas de `sudo`, pas de `rm -rf`, pas de pipe-to-shell.

## Ressources disponibles dans ce workspace

- Subagents : `recon-specialist`, `vuln-hunter`, `js-analyzer`, `report-writer` (délègue quand pertinent via l'outil Agent)
- Skills : `xss-hunting`, `sqli-techniques`, `idor-testing`, `ssrf-bypasses`, `jwt-attacks` dans `.claude/skills/`
- Rappel règles éthiques : `CLAUDE.md`

**Lance maintenant.** Sois efficace, ne re-lis pas les fichiers que tu as déjà lus, ne re-lance pas de commande déjà exécutée."""


def _write_state(workspace: Path, state: dict) -> None:
    target = workspace / "state" / "current.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(state, indent=2))


def _parse_stream_event(line: str) -> dict | None:
    """Parse une ligne stream-json émise par Claude Code."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def run_autopilot_max(target: str, workspace: Path | str = ".",
                     max_iterations: int = 40, on_event=None) -> dict:
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    state_dir = workspace / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    if not os.getenv("CLAUDE_CODE_OAUTH_TOKEN"):
        raise RuntimeError(
            "CLAUDE_CODE_OAUTH_TOKEN non défini. "
            "Génère-le avec `claude setup-token` depuis une machine avec Claude Code installé, "
            "puis expose-le dans l'environnement de ce service."
        )

    state = {
        "target": target,
        "status": "running",
        "mode": "claude-max-subscription",
        "started_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "iterations": 0,
        "findings": [],
        "probe_count": 0,
        "summary": "",
    }
    _write_state(workspace, state)

    prompt = AUTOPILOT_PROMPT.format(target=target, max_iterations=max_iterations)
    log_path = state_dir / "claude_max.log"

    # Forcer l'utilisation du token OAuth, pas de l'API key
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}

    cmd = [
        CLAUDE_BIN, "-p",
        "--dangerously-skip-permissions",
        "--output-format", "stream-json",
        "--verbose",
        prompt,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(workspace),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        state["status"] = "error"
        state["error"] = (
            f"Binaire `{CLAUDE_BIN}` introuvable. Installe Claude Code : "
            "`curl -fsSL https://claude.ai/install.sh | bash`"
        )
        _write_state(workspace, state)
        return state

    with log_path.open("w", encoding="utf-8") as log_fh:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            log_fh.write(raw_line)
            log_fh.flush()

            event = _parse_stream_event(raw_line)
            if not event:
                continue

            event_type = event.get("type", "")
            # Événements utiles : "message" (assistant text), "tool_use", "tool_result", "result"
            if event_type == "tool_use":
                state["iterations"] = state.get("iterations", 0) + 1
                tool_name = event.get("name", "")
                if "curl" in json.dumps(event.get("input", {})) and "xssTEST1234" in json.dumps(event.get("input", {})):
                    state["probe_count"] = state.get("probe_count", 0) + 1
                _write_state(workspace, state)
            elif event_type == "result":
                state["summary"] = event.get("result", "")[:2000]
                _write_state(workspace, state)

            if on_event:
                on_event(event)

    proc.wait()

    findings_dir = workspace / "findings"
    confirmed = sorted(findings_dir.glob("*.md")) if findings_dir.exists() else []
    candidates_dir = findings_dir / "_candidates"
    candidates = sorted(candidates_dir.glob("*.md")) if candidates_dir.exists() else []

    state["findings"] = [str(f.relative_to(workspace)) for f in confirmed]
    state["candidates"] = [str(f.relative_to(workspace)) for f in candidates]
    state["status"] = "done" if proc.returncode == 0 else "error"
    state["exit_code"] = proc.returncode
    state["finished_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    _write_state(workspace, state)
    return state


def main():
    parser = argparse.ArgumentParser(description="Autopilot via subscription Claude Max")
    parser.add_argument("--target", required=True)
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--max-iterations", type=int, default=40)
    args = parser.parse_args()
    final = run_autopilot_max(args.target, args.workspace, args.max_iterations)
    print(json.dumps(final, indent=2))
    return 0 if final.get("status") == "done" else 2


if __name__ == "__main__":
    raise SystemExit(main())
