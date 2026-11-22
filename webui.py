"""
Interface web (Flask) : routes /api/* de l'ancien « Bot Manager », branchées sur
le serveur de keepalive.py (même port, même processus que le bot Telegram).

Sécurité (différences volontaires par rapport au script d'origine) :
  - la vérification d'appareil est appliquée CÔTÉ SERVEUR sur toutes les routes
    /api/* (session signée), pas seulement dans l'écran JavaScript ;
  - plus de mot de passe admin par défaut : WEB_ADMIN_PASSWORD, sinon un mot de
    passe aléatoire est écrit dans les logs au démarrage ;
  - mots de passe des sous-admins hachés ; chemins de fichiers validés ;
  - le token du bot ne figure plus dans le code (voir botconfig.py).
"""

import hmac
import os
import platform
import re
import secrets
import sys
from datetime import timedelta
from functools import wraps

from flask import jsonify, redirect, request, session

import botconfig
import registry
import runlog
import serverinfo
import webscripts
import webstore
from botconfig import _client_ip, _record_failure, _throttle_ok
from keepalive import (DATA_DIR, add_log, app, get_public_domain, keep_alive_enabled,
                       keep_alive_interval, set_keep_alive_enabled, set_keep_alive_interval)

# ==================== CONFIGURATION ====================
MAIN_ADMIN = (os.environ.get("WEB_ADMIN_USER") or "admin").strip() or "admin"
_pw = (os.environ.get("WEB_ADMIN_PASSWORD") or "").strip()
PASSWORD_IS_GENERATED = not _pw
MAIN_ADMIN_PASSWORD = _pw or secrets.token_urlsafe(12)


def _load_secret_key() -> bytes:
    path = os.path.join(DATA_DIR, "web-secret.key")
    try:
        with open(path, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except OSError:
        pass  # clé non persistante : les sessions seront invalidées au redémarrage
    return key


app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE") or "").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)


def announce() -> None:
    if PASSWORD_IS_GENERATED:
        add_log(f"[WebUI] WEB_ADMIN_PASSWORD non défini -> mot de passe admin web temporaire "
                f"(utilisateur « {MAIN_ADMIN} ») : {MAIN_ADMIN_PASSWORD}")


# ==================== GARDES ====================
PUBLIC_API = {"/api/status", "/api/submit-device", "/api/verify-device",
              "/api/admin/login", "/api/admin/logout", "/api/admin/check"}


@app.before_request
def _gate():
    path = request.path
    if not path.startswith("/api/") or path in PUBLIC_API:
        return None
    if session.get("is_admin"):
        return None
    did = session.get("device_id")
    if not did or not webstore.is_allowed(did) or webstore.is_banned(did):
        session.pop("device_id", None)
        return jsonify({"error": "جهاز غير مصرح", "gate": True}), 403
    if registry.get_mode() == "private" and path.startswith("/api/scripts"):
        return jsonify({"error": "الوضع الخاص مفعل", "private_mode": True}), 403
    return None


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return jsonify({"error": "وصول مرفوض"}), 403
        return f(*a, **kw)
    return wrapper


def main_admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_main_admin"):
            return jsonify({"error": "المدير الرئيسي فقط"}), 403
        return f(*a, **kw)
    return wrapper


def _json() -> dict:
    return request.get_json(silent=True) or {}


# ==================== APPAREILS ====================
@app.route("/admin")
def admin_redirect():
    return redirect("./", code=302)


@app.route("/api/status")
def api_status():
    return jsonify({"status": "healthy", "mode": registry.get_mode(),
                    "keep_alive_running": keep_alive_enabled()})


@app.route("/api/verify-device", methods=["POST"])
def verify_device():
    did = webstore.norm(_json().get("device_id"))
    if not webstore.DEVICE_ID_RE.match(did):
        return jsonify({"allowed": False, "banned": False})
    if webstore.is_banned(did):
        session.pop("device_id", None)
        return jsonify({"allowed": False, "banned": True})
    if webstore.is_allowed(did):
        session["device_id"] = did
        session.permanent = True
        return jsonify({"allowed": True, "banned": False})
    return jsonify({"allowed": False, "banned": False})


@app.route("/api/submit-device", methods=["POST"])
def submit_device():
    did = webstore.norm(_json().get("device_id"))
    if not webstore.DEVICE_ID_RE.match(did):
        return jsonify({"success": False}), 400
    if webstore.is_allowed(did):
        return jsonify({"success": True, "status": "allowed"})
    if webstore.is_banned(did):
        return jsonify({"success": True, "status": "banned"})
    req, reason = webstore.add_pending(did, _client_ip(), request.headers.get("User-Agent", ""))
    if req:
        return jsonify({"success": True, "status": "submitted"})
    return jsonify({"success": True, "status": reason})


@app.route("/api/admin/allowed-devices", methods=["GET"])
@admin_required
def get_allowed_devices():
    devices = webstore.allowed_list()
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/admin/allowed-devices", methods=["POST"])
@admin_required
def add_allowed_device():
    did = webstore.norm(_json().get("device_id"))
    if not webstore.DEVICE_ID_RE.match(did):
        return jsonify({"success": False, "error": "المعرف يجب أن يكون 16 خانة (0-9 a-f)"}), 400
    if not webstore.add_allowed(did):
        return jsonify({"success": False, "error": "الجهاز موجود مسبقاً"}), 400
    return jsonify({"success": True, "device_id": did, "total": len(webstore.allowed_list())})


@app.route("/api/admin/allowed-devices", methods=["DELETE"])
@admin_required
def remove_allowed_device():
    did = webstore.norm(_json().get("device_id"))
    if not did:
        return jsonify({"success": False, "error": "المعرف مطلوب"}), 400
    if not webstore.remove_allowed(did):
        return jsonify({"success": False, "error": "الجهاز غير موجود"}), 404
    return jsonify({"success": True, "total": len(webstore.allowed_list())})


# ==================== ADMIN : CONNEXION ====================
@app.route("/api/check-admin-id")
def check_admin_id():
    uid = request.args.get("user_id", "").strip()
    is_admin_id = uid.isdigit() and int(uid) in botconfig.get_admin_ids()
    return jsonify({"is_admin_id": is_admin_id})


@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    ip = _client_ip()
    if not _throttle_ok(ip):
        return jsonify({"success": False, "error": "محاولات كثيرة، حاول لاحقاً"}), 429
    data = _json()
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    is_main = username == MAIN_ADMIN and hmac.compare_digest(
        password.encode("utf-8"), MAIN_ADMIN_PASSWORD.encode("utf-8"))
    if is_main or (username != MAIN_ADMIN and webstore.check_sub_admin(username, password)):
        session["is_admin"] = True
        session["username"] = username
        session["is_main_admin"] = is_main
        session.permanent = True
        return jsonify({"success": True, "is_main_admin": is_main})
    _record_failure(ip)
    return jsonify({"success": False, "error": "بيانات غير صحيحة"}), 401


@app.route("/api/admin/logout")
def api_admin_logout():
    for k in ("is_admin", "username", "is_main_admin"):
        session.pop(k, None)
    return jsonify({"success": True})


@app.route("/api/admin/check")
def api_admin_check():
    return jsonify({"is_admin": bool(session.get("is_admin")),
                    "is_main_admin": bool(session.get("is_main_admin"))})


# ==================== SCRIPTS ====================
def _resolve_folder(data):
    """Dossier cible : « folder » (admin seulement) ou web_<user_id>."""
    if session.get("is_admin") and data.get("folder"):
        return webscripts.valid_folder(data.get("folder"))
    uid = data.get("user_id")
    if uid and webstore.is_banned(uid):
        return None
    return webscripts.web_folder(uid)


@app.route("/api/scripts", methods=["GET"])
def get_scripts():
    folder = _resolve_folder({"user_id": request.args.get("user_id")})
    if not folder:
        return jsonify([])
    return jsonify(webscripts.list_scripts(folder))


@app.route("/api/scripts/upload", methods=["POST"])
def upload_script():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "لا يوجد ملف"}), 400
    folder = _resolve_folder({"user_id": request.form.get("user_id")})
    if not folder:
        return jsonify({"error": "معرف غير صالح (أحرف إنجليزية وأرقام و _ . - فقط)"}), 400
    name = re.sub(r"[^\w.-]", "_", os.path.basename(f.filename))
    if not name.endswith(".py") or name.startswith("."):
        return jsonify({"error": "الملفات المقبولة فقط: .py"}), 400
    base = webscripts.folder_path(folder)
    os.makedirs(base, exist_ok=True)
    existing = [x for x in os.listdir(base) if os.path.isfile(os.path.join(base, x))]
    if not session.get("is_admin") and name not in existing and len(existing) >= webscripts.MAX_USER_SCRIPTS:
        return jsonify({"error": "الحد الأقصى %d سكريبتات" % webscripts.MAX_USER_SCRIPTS}), 400
    path = webscripts.script_path(folder, name, must_exist=False)
    if not path:
        return jsonify({"error": "اسم ملف غير صالح"}), 400
    data = f.read(webscripts.MAX_SCRIPT_BYTES + 1)
    if len(data) > webscripts.MAX_SCRIPT_BYTES:
        return jsonify({"error": "الملف كبير جداً (الحد 1MB)"}), 413
    with open(path, "wb") as out:
        out.write(data)
    return jsonify({"success": True, "filename": name, "install_id": webscripts.start_install(path)})


@app.route("/api/scripts/install-logs/<install_id>")
def get_install_logs(install_id):
    logs = list(webscripts.install_logs.get(install_id, []))
    return jsonify({"logs": logs, "completed": any("[TERMINE]" in x for x in logs)})


@app.route("/api/scripts/run", methods=["POST"])
def run_script():
    data = _json()
    folder = _resolve_folder(data)
    if not folder or not data.get("filename"):
        return jsonify({"error": "معاملات غير صالحة"}), 400
    ok, payload = webscripts.run(folder, str(data["filename"]),
                                 is_admin=bool(session.get("is_admin")), label=str(data.get("user_id") or ""))
    if ok:
        return jsonify({"success": True, **payload})
    return jsonify({"success": False, **payload}), 400


@app.route("/api/scripts/stop", methods=["POST"])
def stop_script():
    data = _json()
    folder = _resolve_folder(data)
    if not folder or not data.get("filename"):
        return jsonify({"error": "معاملات غير صالحة"}), 400
    if webscripts.stop(folder, str(data["filename"])):
        return jsonify({"success": True})
    return jsonify({"error": "غير موجود أو متوقف"}), 404


@app.route("/api/scripts/delete", methods=["DELETE"])
def delete_script():
    data = _json()
    folder = _resolve_folder(data)
    if not folder or not data.get("filename"):
        return jsonify({"error": "معاملات غير صالحة"}), 400
    ok, err = webscripts.delete(folder, str(data["filename"]))
    return jsonify({"success": True}) if ok else (jsonify({"error": err}), 404)


@app.route("/api/scripts/output")
def get_script_output():
    folder = _resolve_folder({"user_id": request.args.get("user_id")})
    fn = request.args.get("filename", "")
    if not folder or not fn or not webscripts.script_path(folder, fn):
        return jsonify({"error": "غير موجود"}), 404
    return jsonify(webscripts.output(folder, fn))


@app.route("/api/scripts/view")
def view_script():
    folder = _resolve_folder({"user_id": request.args.get("user_id")})
    fn = request.args.get("filename", "")
    path = webscripts.script_path(folder, fn) if folder else None
    if not path:
        return jsonify({"error": "غير موجود"}), 404
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return jsonify({"content": fh.read(), "filename": fn})


# ==================== SYSTÈME ====================
def _cpu_info() -> dict:
    try:
        import psutil
        freq = None
        try:
            freq = psutil.cpu_freq()
        except Exception:
            pass
        return {"percent": psutil.cpu_percent(interval=None),
                "count": psutil.cpu_count() or os.cpu_count() or 0,
                "frequency_current": freq.current if freq else 0,
                "frequency_max": freq.max if freq else 0,
                "per_cpu": psutil.cpu_percent(interval=None, percpu=True)}
    except Exception:
        count = os.cpu_count() or 1
        try:
            percent = min(100.0, os.getloadavg()[0] * 100 / count)
        except (AttributeError, OSError):
            percent = 0
        return {"percent": round(percent, 1), "count": count,
                "frequency_current": 0, "frequency_max": 0, "per_cpu": []}


def system_info() -> dict:
    mem = serverinfo.get_memory()
    total, used = mem.get("total") or 0, mem.get("used") or 0
    memory = {"total": total, "used": used, "free": max(total - used, 0),
              "available": max(total - used, 0),
              "percent": round(used * 100 / total, 1) if total else 0}
    du = serverinfo.get_disk(DATA_DIR)
    d_total, d_used = du.get("total") or 0, du.get("used") or 0
    scripts_size, _ = serverinfo.dir_size(webscripts.BASE_DIR)
    disk = {"scripts_size": scripts_size, "total_disk": d_total, "used_disk": d_used,
            "free_disk": du.get("free") or 0,
            "disk_percent": round(d_used * 100 / d_total, 1) if d_total else 0}
    from datetime import datetime
    return {"timestamp": datetime.now().isoformat(), "disk": disk, "memory": memory,
            "cpu": _cpu_info(), "active_processes": webscripts.running_count(),
            "total_scripts_count": webscripts.count_py_scripts(),
            "platform": platform.system(), "python_version": sys.version.split()[0]}


@app.route("/api/system-info")
def api_system_info():
    return jsonify(system_info())


# ==================== ADMIN : GESTION ====================
@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    users, scripts = webscripts.counts()
    return jsonify({
        "total_users": users, "total_scripts": scripts,
        "active_processes": webscripts.running_count(),
        "bot_mode": registry.get_mode(),
        "keep_alive_running": keep_alive_enabled(),
        "keep_alive_interval": keep_alive_interval(),
        "banned_users": webstore.banned_list(),
        "admin_ids": [str(x) for x in botconfig.get_admin_ids()],
        "domain": get_public_domain() or None,
    })


@app.route("/api/admin/all-scripts")
@admin_required
def admin_all_scripts():
    return jsonify(webscripts.list_all())


@app.route("/api/admin/run-log")
@admin_required
def admin_run_log():
    return jsonify(runlog.recent(100))


@app.route("/api/admin/view-script")
@admin_required
def admin_view_script():
    folder = webscripts.valid_folder(request.args.get("user_id"))
    path = webscripts.script_path(folder, request.args.get("filename", "")) if folder else None
    if not path:
        return jsonify({"error": "غير موجود"}), 404
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return jsonify({"content": fh.read(), "filename": request.args.get("filename"), "user_id": folder})


@app.route("/api/admin/mode", methods=["POST"])
@admin_required
def toggle_mode():
    if registry.set_mode(_json().get("mode", "")):
        return jsonify({"success": True, "mode": registry.get_mode()})
    return jsonify({"error": "وضع غير صالح"}), 400


@app.route("/api/admin/keepalive", methods=["POST"])
@admin_required
def toggle_keepalive():
    action = _json().get("action", "")
    if action == "start":
        set_keep_alive_enabled(True)
    elif action == "stop":
        set_keep_alive_enabled(False)
    return jsonify({"success": True, "keep_alive_running": keep_alive_enabled()})


@app.route("/api/admin/keepalive-interval", methods=["POST"])
@admin_required
def update_keepalive_interval():
    try:
        i = int(_json().get("interval"))
    except (TypeError, ValueError):
        i = 0
    if 30 <= i <= 300:
        set_keep_alive_interval(i)
        return jsonify({"success": True, "interval": i})
    return jsonify({"error": "بين 30 و 300 ثانية"}), 400


def _sync_bot_ban(ident, banned: bool) -> None:
    if str(ident).isdigit():
        (registry.bot_banned.add if banned else registry.bot_banned.discard)(int(ident))


@app.route("/api/admin/ban", methods=["POST"])
@admin_required
def ban_user():
    uid = str(_json().get("user_id", "")).strip()
    if not uid:
        return jsonify({"error": "المعرف مطلوب"}), 400
    webstore.ban(uid)
    _sync_bot_ban(uid, True)
    return jsonify({"success": True, "banned_users": webstore.banned_list()})


@app.route("/api/admin/unban", methods=["POST"])
@admin_required
def unban_user():
    uid = str(_json().get("user_id", "")).strip()
    if not uid:
        return jsonify({"error": "المعرف مطلوب"}), 400
    webstore.unban(uid)
    _sync_bot_ban(uid, False)
    return jsonify({"success": True, "banned_users": webstore.banned_list()})


@app.route("/api/admin/add-admin-id", methods=["POST"])
@admin_required
def add_admin_id():
    uid = str(_json().get("user_id", "")).strip()
    if not uid.isdigit():
        return jsonify({"error": "معرف تلغرام يجب أن يكون أرقاماً"}), 400
    botconfig.add_extra_admin(uid)
    if registry.admins is not None:
        registry.admins[:] = botconfig.get_admin_ids()
    return jsonify({"success": True, "admin_ids": [str(x) for x in botconfig.get_admin_ids()]})


@app.route("/api/admin/sub-admin", methods=["POST"])
@main_admin_required
def add_sub_admin():
    data = _json()
    u, p = str(data.get("username", "")).strip(), str(data.get("password", ""))
    if not u or not p:
        return jsonify({"error": "الاسم وكلمة المرور مطلوبان"}), 400
    if u == MAIN_ADMIN:
        return jsonify({"error": "لا يمكن تعديل المدير الرئيسي"}), 400
    if len(p) < 8:
        return jsonify({"error": "كلمة المرور 8 أحرف على الأقل"}), 400
    webstore.add_sub_admin(u, p)
    return jsonify({"success": True})


@app.route("/api/admin/sub-admin", methods=["DELETE"])
@main_admin_required
def remove_sub_admin():
    u = str(_json().get("username", "")).strip()
    if not u:
        return jsonify({"error": "الاسم مطلوب"}), 400
    if webstore.remove_sub_admin(u):
        return jsonify({"success": True})
    return jsonify({"error": "غير موجود"}), 404


@app.route("/api/admin/sub-admins")
@admin_required
def list_sub_admins():
    return jsonify({"sub_admins": webstore.sub_admins_public(),
                    "is_main_admin": bool(session.get("is_main_admin"))})
