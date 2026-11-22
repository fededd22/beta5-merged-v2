"""
Stockage persistant et thread-safe pour l'interface web :
appareils autorisés / bannis, demandes d'accès en attente, comptes admin web.

Fichiers JSON dans DATA_DIR. Utilisé à la fois par Flask (threads) et par le
bot Telegram (boutons ✅ ❌ 🚫).
"""

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from keepalive import DATA_DIR, add_log

_lock = threading.RLock()

ALLOWED_FILE = os.path.join(DATA_DIR, "allowed_devices.json")
BANNED_FILE = os.path.join(DATA_DIR, "banned_users.json")
PENDING_FILE = os.path.join(DATA_DIR, "pending_requests.json")
WEBADMINS_FILE = os.path.join(DATA_DIR, "web_admins.json")

DEVICE_ID_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_PENDING = 100                 # évite l'inondation de demandes
MAX_NEW_REQUESTS_PER_IP = 5       # par heure
_ip_hits = {}                     # ip -> [timestamps]

_notifier = None                  # callback(req: dict) appelé pour chaque nouvelle demande


def set_notifier(cb) -> None:
    global _notifier
    _notifier = cb


# ==================== FICHIERS ====================
def _load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save(path, data) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as e:
        add_log(f"[WebStore] cannot write {path}: {e}")


def norm(device_id) -> str:
    return str(device_id or "").strip().lower()


_allowed = _load(ALLOWED_FILE, {"allowed_ids": [], "added_dates": {}})
_allowed.setdefault("allowed_ids", [])
_allowed.setdefault("added_dates", {})
_banned = set(_load(BANNED_FILE, {"banned": []}).get("banned", []))
_pending = _load(PENDING_FILE, {})
_webadmins = _load(WEBADMINS_FILE, {"sub_admins": {}})
_webadmins.setdefault("sub_admins", {})

# Appareils autorisés au premier démarrage (variable d'environnement, facultatif)
for _d in (os.environ.get("ALLOWED_DEVICE_IDS") or "").replace(" ", "").split(","):
    _d = norm(_d)
    if DEVICE_ID_RE.match(_d) and _d not in _allowed["allowed_ids"]:
        _allowed["allowed_ids"].append(_d)
        _allowed["added_dates"][_d] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
_save(ALLOWED_FILE, _allowed)


# ==================== APPAREILS ====================
def is_allowed(device_id) -> bool:
    d = norm(device_id)
    with _lock:
        return d in _allowed["allowed_ids"]


def is_banned(device_id) -> bool:
    with _lock:
        return str(device_id) in _banned or norm(device_id) in _banned


def allowed_list() -> list:
    with _lock:
        return [{"id": i, "added_date": _allowed["added_dates"].get(i, "")}
                for i in _allowed["allowed_ids"]]


def add_allowed(device_id) -> bool:
    d = norm(device_id)
    with _lock:
        if d in _allowed["allowed_ids"]:
            return False
        _allowed["allowed_ids"].append(d)
        _allowed["added_dates"][d] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _banned.discard(d)
        _save(ALLOWED_FILE, _allowed)
        _save(BANNED_FILE, {"banned": sorted(_banned)})
        return True


def remove_allowed(device_id) -> bool:
    d = norm(device_id)
    with _lock:
        if d not in _allowed["allowed_ids"]:
            return False
        _allowed["allowed_ids"].remove(d)
        _allowed["added_dates"].pop(d, None)
        _save(ALLOWED_FILE, _allowed)
        return True


def ban(ident) -> None:
    """Bannit un appareil ou un identifiant utilisateur (et retire l'accès)."""
    i = str(ident).strip()
    with _lock:
        _banned.add(i)
        _banned.add(i.lower())
        if i.lower() in _allowed["allowed_ids"]:
            _allowed["allowed_ids"].remove(i.lower())
            _allowed["added_dates"].pop(i.lower(), None)
            _save(ALLOWED_FILE, _allowed)
        _save(BANNED_FILE, {"banned": sorted(_banned)})


def unban(ident) -> None:
    i = str(ident).strip()
    with _lock:
        _banned.discard(i)
        _banned.discard(i.lower())
        _save(BANNED_FILE, {"banned": sorted(_banned)})


def banned_list() -> list:
    with _lock:
        return sorted(_banned)


# ==================== DEMANDES EN ATTENTE ====================
def _ip_allowed(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _ip_hits.get(ip, []) if now - t < 3600]
    if len(hits) >= MAX_NEW_REQUESTS_PER_IP:
        _ip_hits[ip] = hits
        return False
    hits.append(now)
    _ip_hits[ip] = hits
    return True


def add_pending(device_id, ip, user_agent):
    """Crée une demande. Retourne (dict, None) ou (None, raison)."""
    d = norm(device_id)
    with _lock:
        for r in _pending.values():
            if r.get("simple_id") == d and r.get("status") == "pending":
                return None, "already_pending"
        if sum(1 for r in _pending.values() if r.get("status") == "pending") >= MAX_PENDING:
            return None, "too_many"
        if not _ip_allowed(ip):
            return None, "rate_limited"
        rid = uuid.uuid4().hex[:8]
        req = {
            "request_id": rid, "simple_id": d, "ip_address": ip,
            "user_agent": str(user_agent or "")[:200] or "unknown",
            "date": datetime.now().isoformat(), "status": "pending",
        }
        _pending[rid] = req
        # purge des anciennes demandes traitées
        done = [k for k, v in _pending.items() if v.get("status") != "pending"]
        for k in done[:-100]:
            _pending.pop(k, None)
        _save(PENDING_FILE, _pending)
    if _notifier:
        try:
            _notifier(dict(req))
        except Exception as e:
            add_log(f"[WebStore] notifier failed: {e}")
    return req, None


def get_request(rid):
    with _lock:
        r = _pending.get(rid)
        return dict(r) if r else None


def set_status(rid, status, by="") -> bool:
    with _lock:
        r = _pending.get(rid)
        if not r:
            return False
        r["status"] = status
        r["processed_by"] = str(by)
        r["processed_date"] = datetime.now().isoformat()
        _save(PENDING_FILE, _pending)
        return True


def pending_list() -> list:
    with _lock:
        return [dict(v) for v in _pending.values() if v.get("status") == "pending"]


def counts() -> dict:
    with _lock:
        out = {"allowed": len(_allowed["allowed_ids"]), "banned": len(_banned),
               "pending": 0, "accepted": 0, "rejected": 0}
        for v in _pending.values():
            s = v.get("status")
            if s in out:
                out[s] += 1
        return out


# ==================== ADMINS WEB ====================
def sub_admins_public() -> dict:
    with _lock:
        return {u: {"added_date": v.get("added_date", "")} for u, v in _webadmins["sub_admins"].items()}


def add_sub_admin(username, password) -> None:
    with _lock:
        _webadmins["sub_admins"][username] = {
            "pw_hash": generate_password_hash(password),
            "added_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        _save(WEBADMINS_FILE, _webadmins)


def remove_sub_admin(username) -> bool:
    with _lock:
        if username not in _webadmins["sub_admins"]:
            return False
        del _webadmins["sub_admins"][username]
        _save(WEBADMINS_FILE, _webadmins)
        return True


def check_sub_admin(username, password) -> bool:
    with _lock:
        rec = _webadmins["sub_admins"].get(username)
    return bool(rec and check_password_hash(rec["pw_hash"], password))
