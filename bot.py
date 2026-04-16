"""
Bot Telegram pour piloter BugBounty-AI depuis ton téléphone.

Setup :
1. Crée un bot via @BotFather sur Telegram → récupère le token
2. Récupère ton chat_id (envoie /start au bot puis https://api.telegram.org/bot<TOKEN>/getUpdates)
3. Configure :
   export TELEGRAM_BOT_TOKEN=...
   export TELEGRAM_ALLOWED_CHATS=123456789,987654321  # whitelist (obligatoire)
   export ANTHROPIC_API_KEY=sk-ant-...
4. Lance : python3 bot.py

Commandes :
    /scan <domain> [autopilot|pipeline|recon]   — démarre un scan
    /status                                      — état du scan en cours
    /findings                                    — liste les findings
    /finding <slug>                              — affiche un finding
    /scope                                       — affiche scope.txt
    /scopeadd <domain>                           — ajoute au scope
    /cancel                                      — annule le scan en cours
    /help                                        — aide
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / "state"
FINDINGS_DIR = ROOT / "findings"
SCOPE_FILE = ROOT / "scope.txt"

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED = {
    int(x.strip())
    for x in os.getenv("TELEGRAM_ALLOWED_CHATS", "").split(",")
    if x.strip().lstrip("-").isdigit()
}

CURRENT_PROC: dict[str, subprocess.Popen] = {}


def _check_deps() -> None:
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN non défini.")
    if not ALLOWED:
        raise SystemExit("TELEGRAM_ALLOWED_CHATS non défini ou vide. "
                         "Sécurité : un bot sans whitelist est exposé à tout Telegram.")
    try:
        import telegram  # noqa: F401
        from telegram.ext import Application  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "python-telegram-bot manquant. Installe avec : "
            "pip install 'python-telegram-bot>=21.0'"
        ) from exc


def _scope() -> list[str]:
    if not SCOPE_FILE.exists():
        return []
    return [
        line.strip()
        for line in SCOPE_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _state() -> dict:
    f = STATE_DIR / "current.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except json.JSONDecodeError:
        return {}


def _is_scan_running() -> bool:
    for sid, proc in list(CURRENT_PROC.items()):
        if proc.poll() is None:
            return True
        del CURRENT_PROC[sid]
    return False


def main():
    _check_deps()

    from telegram import Update
    from telegram.constants import ParseMode
    from telegram.ext import Application, CommandHandler, ContextTypes, filters

    def whitelist_only(handler):
        async def wrapped(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            if update.effective_chat is None or update.effective_chat.id not in ALLOWED:
                if update.effective_chat:
                    await update.effective_chat.send_message(
                        f"Accès refusé. Ton chat_id : {update.effective_chat.id}"
                    )
                return
            return await handler(update, ctx)
        return wrapped

    @whitelist_only
    async def cmd_help(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "*Commandes BugBounty-AI*\n\n"
            "/scan <domain> [autopilot|pipeline|recon] — démarre un scan\n"
            "/status — état du scan en cours\n"
            "/findings — liste des findings\n"
            "/finding <slug> — détail d'un finding\n"
            "/scope — affiche scope.txt\n"
            "/scopeadd <domain> — ajoute un domaine au scope\n"
            "/cancel — annule le scan en cours\n",
            parse_mode=ParseMode.MARKDOWN,
        )

    @whitelist_only
    async def cmd_scope(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
        s = _scope()
        msg = "\n".join(f"• {d}" for d in s) if s else "_(scope vide)_"
        await update.message.reply_text(f"*Scope actuel*\n{msg}", parse_mode=ParseMode.MARKDOWN)

    @whitelist_only
    async def cmd_scopeadd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not ctx.args:
            await update.message.reply_text("Usage : `/scopeadd <domain>`", parse_mode=ParseMode.MARKDOWN)
            return
        existing = _scope()
        added = []
        if not SCOPE_FILE.exists():
            SCOPE_FILE.write_text("# Domaines autorisés\n")
        with SCOPE_FILE.open("a") as fh:
            for raw in ctx.args:
                d = raw.strip().lower()
                if d and d not in existing:
                    fh.write(d + "\n")
                    added.append(d)
        await update.message.reply_text(
            f"Ajoutés : {', '.join(added)}" if added else "Rien à ajouter (déjà présent)."
        )

    @whitelist_only
    async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if _is_scan_running():
            await update.message.reply_text("Un scan tourne déjà. /cancel pour l'arrêter, /status pour voir.")
            return
        if not ctx.args:
            await update.message.reply_text("Usage : `/scan <domain> [autopilot|pipeline|recon]`",
                                            parse_mode=ParseMode.MARKDOWN)
            return
        target = ctx.args[0].strip().lower()
        mode = ctx.args[1].lower() if len(ctx.args) > 1 else "autopilot"
        if target not in _scope():
            await update.message.reply_text(
                f"❌ `{target}` absent de scope.txt. Utilise /scopeadd d'abord.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return
        if mode == "autopilot":
            cmd = ["python3", "-u", "autopilot.py", "--target", target]
        elif mode == "pipeline":
            cmd = ["python3", "-u", "IABounty.py", "--target", target, "--claude"]
        elif mode == "recon":
            cmd = ["python3", "-u", "IABounty.py", "--target", target]
        else:
            await update.message.reply_text(f"Mode inconnu : {mode}")
            return
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        log_fh = (STATE_DIR / "stdout.log").open("w")
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log_fh, stderr=subprocess.STDOUT)
        CURRENT_PROC[str(proc.pid)] = proc
        await update.message.reply_text(
            f"🚀 Scan lancé sur `{target}` (mode `{mode}`, pid {proc.pid}).\n"
            f"Use /status pour suivre.",
            parse_mode=ParseMode.MARKDOWN,
        )
        ctx.job_queue.run_repeating(
            _watch_completion, interval=15, first=15,
            data={"chat_id": update.effective_chat.id, "pid": proc.pid, "target": target},
            name=f"watch_{proc.pid}",
        )

    async def _watch_completion(ctx: ContextTypes.DEFAULT_TYPE):
        data = ctx.job.data
        proc = CURRENT_PROC.get(str(data["pid"]))
        if proc is None or proc.poll() is not None:
            ctx.job.schedule_removal()
            state = _state()
            findings = state.get("findings", [])
            await ctx.bot.send_message(
                data["chat_id"],
                f"✅ Scan terminé pour *{data['target']}*\n"
                f"Status : `{state.get('status', 'unknown')}`\n"
                f"Findings : {len(findings)}\n"
                f"Itérations : {state.get('iterations', 0)}\n\n"
                f"{state.get('summary', '')[:500]}",
                parse_mode=ParseMode.MARKDOWN,
            )
            CURRENT_PROC.pop(str(data["pid"]), None)

    @whitelist_only
    async def cmd_status(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
        state = _state()
        if not state:
            await update.message.reply_text("Aucun scan enregistré.")
            return
        msg = (
            f"*Scan actuel*\n"
            f"Cible : `{state.get('target', '?')}`\n"
            f"Statut : `{state.get('status', '?')}`\n"
            f"Itérations : {state.get('iterations', 0)}\n"
            f"Findings : {len(state.get('findings', []))}\n"
            f"Probes XSS : {state.get('probe_count', 0)}\n"
        )
        if state.get("summary"):
            msg += f"\n_Résumé :_\n{state['summary'][:800]}"
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

    @whitelist_only
    async def cmd_findings(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
        confirmed = sorted(FINDINGS_DIR.glob("*.md")) if FINDINGS_DIR.exists() else []
        cands = sorted((FINDINGS_DIR / "_candidates").glob("*.md")) if (FINDINGS_DIR / "_candidates").exists() else []
        msg = "*Confirmed* (" + str(len(confirmed)) + ")\n"
        msg += "\n".join(f"• `{f.stem}`" for f in confirmed) or "_(aucun)_"
        msg += "\n\n*Candidates* (" + str(len(cands)) + ")\n"
        msg += "\n".join(f"• `{f.stem}`" for f in cands) or "_(aucun)_"
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

    @whitelist_only
    async def cmd_finding(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not ctx.args:
            await update.message.reply_text("Usage : `/finding <slug>`", parse_mode=ParseMode.MARKDOWN)
            return
        slug = ctx.args[0].strip()
        for folder in (FINDINGS_DIR, FINDINGS_DIR / "_candidates"):
            target = folder / f"{slug}.md"
            if target.exists():
                content = target.read_text()
                # Telegram limite : 4096 chars par message
                for i in range(0, len(content), 3500):
                    await update.message.reply_text(content[i:i + 3500])
                return
        await update.message.reply_text(f"Finding `{slug}` introuvable.", parse_mode=ParseMode.MARKDOWN)

    @whitelist_only
    async def cmd_cancel(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
        killed = 0
        for sid, proc in list(CURRENT_PROC.items()):
            if proc.poll() is None:
                proc.terminate()
                killed += 1
            CURRENT_PROC.pop(sid, None)
        await update.message.reply_text(f"Stoppé : {killed} process.")

    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler(["start", "help"], cmd_help))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("findings", cmd_findings))
    app.add_handler(CommandHandler("finding", cmd_finding))
    app.add_handler(CommandHandler("scope", cmd_scope))
    app.add_handler(CommandHandler("scopeadd", cmd_scopeadd))
    app.add_handler(CommandHandler("cancel", cmd_cancel))

    print(f"[+] Bot démarré. Whitelist chat_ids : {sorted(ALLOWED)}")
    app.run_polling()


if __name__ == "__main__":
    main()
