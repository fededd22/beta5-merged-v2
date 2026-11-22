"""Journal persistant des exécutions de scripts (Telegram + web) : qui, quoi, quand."""

import json
import os
import threading
from datetime import datetime

from keepalive import DATA_DIR, add_log

_lock = threading.Lock()
FILE = os.path.join(DATA_DIR, "run-log.json")
MAX_ENTRIES = 500

try:
    with open(FILE, "r", encoding="utf-8") as _f:
        _entries = json.load(_f)
except (OSError, ValueError):
    _entries = []


def _save() -> None:
    tmp = FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_entries, f, ensure_ascii=False)
        os.replace(tmp, FILE)
    except OSError as e:
        add_log(f"[RunLog] cannot write: {e}")


def add(source, folder, user_id, name, filename, status, pid=None, reasons=None) -> dict:
    """status: 'started' | 'blocked'. folder = dossier du script (clé de regroupement)."""
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source, "folder": str(folder), "user_id": str(user_id),
        "name": str(name or ""), "filename": filename, "status": status,
        "pid": pid, "reasons": reasons or [],
    }
    with _lock:
        _entries.append(entry)
        del _entries[:-MAX_ENTRIES]
        _save()
    return entry


def recent(n: int = 50) -> list:
    with _lock:
        return list(reversed(_entries[-n:]))


def last_run(folder, filename):
    """(dernière exécution réussie, nombre d'exécutions) pour un script."""
    last, count = "", 0
    with _lock:
        for e in _entries:
            if e["folder"] == str(folder) and e["filename"] == filename and e["status"] == "started":
                last, count = e["time"], count + 1
    return last, count
