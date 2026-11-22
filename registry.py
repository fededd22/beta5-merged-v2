"""
État partagé entre le bot Telegram (asyncio, thread principal) et l'interface
web (Flask, threads) : mode public/privé, admins, scripts lancés par le bot.

Le bot renseigne ces références au démarrage (istidafa4_by_moon.py) ; l'interface
web les lit. Rien ici ne dépend d'aiogram ou de Flask.
"""

import asyncio
import threading

_lock = threading.Lock()
_mode = "public"          # "public" | "private"

admins = []               # liste des IDs Telegram admins (même objet que ADMINS du bot)
bot_processes = {}        # (user_id:int, fichier) -> asyncio.subprocess.Process
bot_banned = set()        # IDs Telegram bannis (même objet que banned_users du bot)
loop = None               # boucle asyncio du bot
stop_cb = None            # coroutine stop_process(key, reason) du bot


event_cb = None           # callback(event: dict, path: str) -> notifie les admins (défini par le bot)


def notify_script_event(event: dict, path: str) -> None:
    """Appelable depuis n'importe quel thread : envoie l'événement + le fichier aux admins."""
    if event_cb:
        try:
            event_cb(event, path)
        except Exception:
            pass


def get_mode() -> str:
    return _mode


def set_mode(mode: str) -> bool:
    global _mode
    if mode not in ("public", "private"):
        return False
    with _lock:
        _mode = mode
    return True


def running_bot_count() -> int:
    return sum(1 for p in list(bot_processes.values()) if p.returncode is None)


def is_bot_script_running(user_id: int, filename: str) -> bool:
    p = bot_processes.get((user_id, filename))
    return bool(p and p.returncode is None)


def stop_bot_script(user_id: int, filename: str, timeout: float = 25.0) -> bool:
    """Arrête (depuis un thread Flask) un script lancé par le bot Telegram."""
    if loop is None or stop_cb is None:
        return False
    fut = asyncio.run_coroutine_threadsafe(stop_cb((user_id, filename), "admin"), loop)
    try:
        return bool(fut.result(timeout=timeout))
    except Exception:
        return False
