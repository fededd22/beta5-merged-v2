"""
Gestion des scripts depuis l'interface web (threads, subprocess).

- Les scripts « web » vivent dans DATA_DIR/scripts/web_<id> : ils ne se mélangent
  pas avec ceux des utilisateurs Telegram (DATA_DIR/scripts/<id numérique>).
- La sortie des scripts va dans un fichier log (jamais dans un pipe non lu, qui
  finirait par bloquer le script quand le tampon est plein).
- Les chemins sont validés : aucun `..`, aucun lien symbolique hors du dossier.
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

import libs
import registry
import runlog
import scriptguard
from keepalive import DATA_DIR, add_log

BASE_DIR = os.path.join(DATA_DIR, "scripts")
LOG_DIR = os.path.join(DATA_DIR, "weblogs")
WEB_PREFIX = "web_"
MAX_SCRIPT_BYTES = 1024 * 1024
MAX_USER_SCRIPTS = 4
LOG_TAIL_BYTES = 20000

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

_UID_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_FOLDER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,80}$")

_lock = threading.Lock()
_procs = {}        # (folder, fichier) -> subprocess.Popen
_finished = {}     # (folder, fichier) -> code de sortie
install_logs = {}  # install_id -> [lignes]


# ==================== CHEMINS ====================
def web_folder(user_id):
    """Dossier d'un utilisateur web (préfixe web_) ou None si l'identifiant est invalide."""
    uid = str(user_id or "").strip()
    if not _UID_RE.match(uid):
        return None
    return WEB_PREFIX + uid


def valid_folder(name):
    name = str(name or "")
    return name if _FOLDER_RE.match(name) and not name.startswith(".") else None


def folder_path(folder):
    folder = valid_folder(folder)
    if not folder:
        return None
    path = os.path.realpath(os.path.join(BASE_DIR, folder))
    if os.path.dirname(path) != os.path.realpath(BASE_DIR):
        return None
    return path


def script_path(folder, filename, must_exist=True):
    """Chemin sûr d'un script, ou None."""
    fn = str(filename or "")
    if not fn or fn != os.path.basename(fn) or "\x00" in fn or fn.startswith("."):
        return None
    base = folder_path(folder)
    if not base:
        return None
    path = os.path.realpath(os.path.join(base, fn))
    if os.path.dirname(path) != base:
        return None
    if must_exist and not os.path.isfile(path):
        return None
    return path


# ==================== ÉTAT ====================
def status(folder, filename) -> str:
    if folder.isdigit():  # dossier d'un utilisateur Telegram : état fourni par le bot
        return "running" if registry.is_bot_script_running(int(folder), filename) else "stopped"
    key = (folder, filename)
    with _lock:
        p = _procs.get(key)
        if p is None:
            return "stopped"
        rc = p.poll()
        if rc is None:
            return "running"
        _finished[key] = rc
        del _procs[key]
        return "stopped"


def list_scripts(folder) -> list:
    base = folder_path(folder)
    out = []
    if base and os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if os.path.isfile(p):
                out.append({"filename": name, "status": status(folder, name), "size": os.path.getsize(p)})
    return out


def list_all() -> list:
    res = []
    try:
        for folder in sorted(os.listdir(BASE_DIR)):
            if valid_folder(folder) and folder_path(folder) and os.path.isdir(os.path.join(BASE_DIR, folder)):
                for s in list_scripts(folder):
                    s["user_id"] = folder
                    s["last_run"], s["runs"] = runlog.last_run(folder, s["filename"])
                    res.append(s)
    except OSError:
        pass
    return res


def counts() -> tuple:
    """(utilisateurs, scripts) sur tout le stockage."""
    users = scripts = 0
    try:
        for folder in os.listdir(BASE_DIR):
            fp = os.path.join(BASE_DIR, folder)
            if os.path.isdir(fp):
                users += 1
                scripts += sum(1 for f in os.listdir(fp) if os.path.isfile(os.path.join(fp, f)))
    except OSError:
        pass
    return users, scripts


def count_py_scripts() -> int:
    n = 0
    try:
        for folder in os.listdir(BASE_DIR):
            fp = os.path.join(BASE_DIR, folder)
            if os.path.isdir(fp):
                n += sum(1 for f in os.listdir(fp) if f.endswith(".py"))
    except OSError:
        pass
    return n


def running_count() -> int:
    with _lock:
        return sum(1 for p in _procs.values() if p.poll() is None) + registry.running_bot_count()


# ==================== EXÉCUTION ====================
def _script_env(enforce: bool = True) -> dict:
    # Le token du bot et les mots de passe ne sont pas transmis aux scripts
    secret = {"TELEGRAM_BOT_TOKEN", "MURAD_SETUP_PASSWORD", "WEB_ADMIN_PASSWORD"}
    env = {k: v for k, v in os.environ.items() if k not in secret}
    env["PYTHONPATH"] = os.pathsep.join(p for p in (env.get("PYTHONPATH"), libs.LIBS_DIR) if p)
    return scriptguard.build_env(env, enforce)


def log_file(folder, filename) -> str:
    d = os.path.join(LOG_DIR, folder)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, filename + ".log")


def run(folder, filename, is_admin=False, label=""):
    """Retourne (ok, {...}). Les non-admins passent par la garde et sont journalisés."""
    if not folder.startswith(WEB_PREFIX):
        return False, {"error": "التشغيل من الواجهة متاح فقط لسكريبتات الويب (سكريبتات تلغرام تُشغَّل من البوت)"}
    path = script_path(folder, filename)
    if not path:
        return False, {"error": "غير موجود"}
    if status(folder, filename) == "running":
        return False, {"error": "قيد التشغيل"}
    uid_label = folder[len(WEB_PREFIX):]
    if not is_admin:
        verdict = scriptguard.scan_file(path)
        if verdict.blocked:
            entry = runlog.add("web", folder, uid_label, label or uid_label, filename, "blocked",
                               reasons=verdict.reasons)
            add_log(f"[Guard] web script blocked {filename} ({folder}): {verdict.reasons}")
            registry.notify_script_event(entry, path)
            return False, {"error": "تم رفض تشغيل الملف:\n" + scriptguard.explain(verdict)
                           + "\n\nلا يُسمح باستضافة ملفات بايثون أخرى ولا بمحاولة إيقاف البوت الرئيسي.",
                           "blocked": True, "reasons": verdict.reasons}
    try:
        logf = open(log_file(folder, filename), "wb")
        try:
            proc = subprocess.Popen(
                [sys.executable, "-u", path],
                stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env=_script_env(enforce=not is_admin), cwd=os.path.dirname(path), start_new_session=True,
            )
        finally:
            logf.close()  # le processus fils garde son propre descripteur
    except Exception as e:
        return False, {"error": str(e)}
    with _lock:
        _procs[(folder, filename)] = proc
        _finished.pop((folder, filename), None)
    entry = runlog.add("web", folder, uid_label, label or uid_label, filename, "started", pid=proc.pid)
    if not is_admin:
        registry.notify_script_event(entry, path)
    time.sleep(1)
    rc = proc.poll()
    if rc is not None and rc != 0:
        return False, {"error": "انتهى السكريبت بخطأ (code %s):\n%s" % (rc, read_log(folder, filename))}
    return True, {"pid": proc.pid}


def _signal_group(proc, sig):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


def stop(folder, filename) -> bool:
    if folder.isdigit():
        return registry.stop_bot_script(int(folder), filename)
    key = (folder, filename)
    with _lock:
        proc = _procs.get(key)
    if not proc or proc.poll() is not None:
        return False
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    with _lock:
        _finished[key] = proc.returncode
        _procs.pop(key, None)
    return True


def delete(folder, filename):
    """Retourne (ok, erreur)."""
    path = script_path(folder, filename)
    if not path:
        return False, "غير موجود"
    stop(folder, filename)
    try:
        os.remove(path)
        lf = log_file(folder, filename)
        if os.path.exists(lf):
            os.remove(lf)
    except OSError as e:
        return False, str(e)
    return True, ""


def read_log(folder, filename) -> str:
    lf = log_file(folder, filename)
    try:
        size = os.path.getsize(lf)
        with open(lf, "rb") as f:
            if size > LOG_TAIL_BYTES:
                f.seek(size - LOG_TAIL_BYTES)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def output(folder, filename) -> dict:
    st = status(folder, filename)
    with _lock:
        proc = _procs.get((folder, filename))
        rc = _finished.get((folder, filename))
    if st == "running":
        return {"status": "running", "pid": proc.pid if proc else None, "log": read_log(folder, filename)}
    if folder.isdigit():
        return {"status": "not_found", "log": ""}
    if rc is not None or os.path.exists(log_file(folder, filename)):
        return {"status": "completed", "returncode": rc, "log": read_log(folder, filename)}
    return {"status": "not_found", "log": ""}


# ==================== INSTALLATION DES BIBLIOTHÈQUES ====================
def start_install(path) -> str:
    install_id = str(uuid.uuid4())
    if len(install_logs) > 50:  # pas de croissance infinie
        for k in list(install_logs)[:25]:
            install_logs.pop(k, None)
    install_logs[install_id] = []
    threading.Thread(target=_install_worker, args=(path, install_id), daemon=True).start()
    return install_id


def _install_worker(path, install_id):
    log = install_logs[install_id]
    log.append("[INFO] تحليل: " + os.path.basename(path))
    try:
        missing = libs.find_missing_libraries(path)
    except Exception as e:
        log.append("[ERROR] " + str(e))
        log.append("[TERMINE]")
        return
    if not missing:
        log.append("[OK] كل المكتبات مثبتة")
    ok_count = 0
    for lib in missing:
        log.append("[INSTALL] " + lib + "...")
        try:
            proc = subprocess.Popen(
                [*libs.PIP_CMD, "install", "--no-input", "--progress-bar", "off",
                 "--target", libs.LIBS_DIR, lib],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            timer = threading.Timer(libs.PIP_TIMEOUT_S, proc.kill)
            timer.start()
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if line:
                        log.append("[LOG] " + line[:200])
                proc.wait()
            finally:
                timer.cancel()
            if proc.returncode == 0:
                ok_count += 1
                log.append("[SUCCESS] " + lib + " تم تثبيته!")
            else:
                log.append("[ERROR] فشل تثبيت " + lib)
        except Exception as e:
            log.append("[ERROR] " + str(e))
    libs._ensure_libs_on_path()
    log.append("[RESUME] %d/%d" % (ok_count, len(missing)))
    log.append("[TERMINE]")
    add_log(f"[WebUI] install finished for {os.path.basename(path)}: {ok_count}/{len(missing)}")
