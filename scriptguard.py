"""
Garde des scripts utilisateurs (Telegram + web).

1. Détecte les scripts qui sont eux-mêmes une « plateforme d'hébergement » de scripts
   Python (réception de fichiers .py + exécution + installation de bibliothèques) :
   leur exécution est refusée aux non-admins.
2. Détecte les tentatives d'arrêter le bot principal / des processus système
   (os.kill sur le parent, pkill, taskkill, /proc/*/environ, fichiers du système...).
3. Protection à l'exécution : un `sitecustomize.py` injecté dans l'environnement du
   script bloque os.kill / os.killpg visant le bot principal ou PID 1.

Limite honnête : l'analyse statique ne peut pas arrêter un code volontairement obfusqué
(ctypes, exec dynamique...). Pour une isolation réelle, lancez les scripts dans un
conteneur/utilisateur séparé ; ici c'est une défense en profondeur.
"""

import ast
import io
import os
import re
import tokenize
from dataclasses import dataclass, field

from keepalive import DATA_DIR

MAX_SCAN_BYTES = 1024 * 1024

BOT_FRAMEWORKS = {"telebot", "aiogram", "telegram", "pyrogram", "telethon", "flask",
                  "fastapi", "discord", "http", "aiohttp", "bottle", "tornado"}
SPAWN_CALLS = {
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "os.system", "os.popen", "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell", "runpy.run_path", "runpy.run_module",
}
SPAWN_BARE = {"Popen", "check_output", "check_call", "create_subprocess_exec",
              "create_subprocess_shell", "run_path", "run_module"}
DOC_CALLS = {"get_file", "download_file", "download_media", "save_file", "get_document"}
KILL_CALLS = {"os.kill", "os.killpg", "signal.pthread_kill"}
KILL_TARGET_FUNCS = {"getppid", "getpgrp", "getpgid", "getsid"}
HOST_KEYWORDS = ("hosting", "host python", "استضافة", "run script", "upload script")

KILL_REGEX = re.compile(
    r"\b(pkill|killall|taskkill|skill)\b"
    r"|\bkill\s+(-[A-Za-z0-9]+\s+)*(\$\$|\$PPID|\$\{PPID\}|1\b|-1\b|0\b)"
    r"|\$PPID|\$\{PPID\}", re.IGNORECASE)
SYSFILE_REGEX = re.compile(
    r"/proc/[^\s'\"]*/(environ|mem|cmdline)|istidafa4_by_moon|murad-bot\.json|"
    r"web-secret\.key|web_admins\.json|extra-admins\.json|allowed_devices\.json|"
    r"banned_users\.json|pending_requests\.json|BOT_MAIN_PID", re.IGNORECASE)


@dataclass
class Verdict:
    blocked: bool = False
    hosting: bool = False
    kill: bool = False
    sysfiles: bool = False
    reasons: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _strip_comments(src: str) -> str:
    try:
        toks = [t[:2] for t in tokenize.generate_tokens(io.StringIO(src).readline)
                if t.type != tokenize.COMMENT]
        return tokenize.untokenize(toks)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return src


def _const_strs(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n.value


def _is_risky_kill_arg(arg) -> bool:
    for n in ast.walk(arg):
        if isinstance(n, ast.Call):
            name = _dotted(n.func).split(".")[-1]
            if name in KILL_TARGET_FUNCS:
                return True
        if isinstance(n, (ast.Name, ast.Attribute)):
            ident = n.id if isinstance(n, ast.Name) else n.attr
            if "MAIN_PID" in ident.upper() or "PARENT" in ident.upper():
                return True
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, str)):
            if isinstance(n.value, int) and not isinstance(n.value, bool) and n.value <= 1:
                return True
            if isinstance(n.value, str) and "MAIN_PID" in n.value.upper():
                return True
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub) and isinstance(n.operand, ast.Constant):
            return True
    return False


def scan_source(source: str) -> Verdict:
    v = Verdict()
    clean = _strip_comments(source)

    # ---- expressions régulières (commandes shell, fichiers système) ----
    if KILL_REGEX.search(clean):
        v.kill = True
        v.reasons.append("أوامر إيقاف عمليات (pkill/killall/taskkill/kill) قد تطفئ البوت الرئيسي")
    if SYSFILE_REGEX.search(clean):
        v.sysfiles = True
        v.reasons.append("محاولة الوصول إلى ملفات أو أسرار النظام (/proc أو ملفات إعداد البوت)")

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        tree = None

    if tree is not None:
        imports, attrs, calls, consts = set(), set(), [], []
        has_doc = has_py_check = spawns = has_exec_open = False
        has_pip_word = has_install_word = False
        psutil_iter = psutil_kill = False

        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imports.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                imports.add(n.module.split(".")[0])
            elif isinstance(n, ast.Attribute):
                attrs.add(_dotted(n) or n.attr)
                if n.attr == "document":
                    has_doc = True
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                consts.append(n.value)
                low = n.value.lower()
                if low in ("*.py", "**/*.py"):
                    has_py_check = True
                if low == "pip" or low.startswith("pip "):
                    has_pip_word = True
                if low == "install" or " install" in low:
                    has_install_word = True
            elif isinstance(n, ast.Compare):
                if any(isinstance(x, ast.Constant) and x.value == ".py"
                       for x in [n.left, *n.comparators]):
                    has_py_check = True
            elif isinstance(n, ast.Call):
                name = _dotted(n.func)
                last = name.split(".")[-1] if name else (
                    n.func.attr if isinstance(n.func, ast.Attribute) else "")
                calls.append((name, last, n))
                if last in DOC_CALLS or name == "request.files":
                    has_doc = True
                if last == "endswith" and any(".py" in s for a in n.args for s in _const_strs(a)):
                    has_py_check = True
                if name in SPAWN_CALLS or (name in SPAWN_BARE) or (isinstance(n.func, ast.Name) and n.func.id in SPAWN_BARE):
                    spawns = True
                if isinstance(n.func, ast.Name) and n.func.id in ("exec", "execfile") and any(
                        isinstance(x, ast.Call) and _dotted(x.func).split(".")[-1] == "open"
                        for a in n.args for x in ast.walk(a)):
                    has_exec_open = True
                if name in KILL_CALLS and any(_is_risky_kill_arg(a) for a in n.args[:1]):
                    v.kill = True
                    v.reasons.append("os.kill/killpg يستهدف العملية الأم أو البوت الرئيسي أو PID خاص")
                if name.endswith("process_iter"):
                    psutil_iter = True
                if last in ("kill", "terminate", "send_signal"):
                    psutil_kill = True
                    # psutil.Process(os.getppid()).kill() / x.parent().kill()
                    inner = n.func.value if isinstance(n.func, ast.Attribute) else None
                    if isinstance(inner, ast.Call):
                        inner_last = _dotted(inner.func).split(".")[-1] or (
                            inner.func.attr if isinstance(inner.func, ast.Attribute) else "")
                        if inner_last in ("parent", "parents") or (
                                inner_last == "Process" and any(_is_risky_kill_arg(a) for a in inner.args)):
                            v.kill = True
                            v.reasons.append("إيقاف العملية الأم عبر psutil")
        if psutil_iter and psutil_kill:
            v.kill = True
            v.reasons.append("المرور على عمليات النظام وإيقافها (psutil.process_iter)")

        # ---- détection d'une plateforme d'hébergement ----
        spawns_python = (spawns and ("sys.executable" in attrs
                                     or any("python" in c.lower() for c in consts))) \
            or has_exec_open or any(n[0].startswith("runpy.") for n in calls)
        score = 0
        score += 2 if has_doc else 0
        score += 2 if has_py_check else 0
        score += 3 if spawns_python else 0
        score += 1 if (has_pip_word and has_install_word) else 0
        score += 1 if imports & BOT_FRAMEWORKS else 0
        score += 1 if any(k in c.lower() for c in consts for k in HOST_KEYWORDS) else 0
        if spawns_python and (has_doc or has_py_check) and score >= 6:
            v.hosting = True
            v.reasons.append("الملف يبدو استضافة ملفات بايثون (يستقبل ملفات .py ويشغّلها ويثبّت مكتباتها)")

        # ---- avertissement : code obfusqué (non bloquant) ----
        if re.search(r"\b(exec|eval)\s*\(\s*(base64|zlib|marshal|codecs|bytes|compile)", clean):
            v.warnings.append("كود مشفّر/مبهم (exec على بيانات مشفرة) لا يمكن فحصه")

    v.reasons = list(dict.fromkeys(v.reasons))
    v.blocked = v.hosting or v.kill or v.sysfiles
    return v


def scan_file(path: str) -> Verdict:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_SCAN_BYTES + 1)
    except OSError as e:
        return Verdict(blocked=True, reasons=[f"تعذر قراءة الملف: {e}"])
    if len(raw) > MAX_SCAN_BYTES:
        return Verdict(blocked=True, reasons=["الملف كبير جداً للفحص"])
    return scan_source(raw.decode("utf-8", errors="replace"))


# ==================== PROTECTION À L'EXÉCUTION ====================
GUARD_DIR = os.path.join(DATA_DIR, "guard")
_SITECUSTOMIZE = '''\
# Injecté par l'hébergeur : empêche un script utilisateur de tuer le bot principal.
import os as _os
try:
    _main = int(_os.environ.get("BOT_MAIN_PID") or 0)
except ValueError:
    _main = 0
if _main:
    try:
        _main_pgid = _os.getpgid(_main)
    except Exception:
        _main_pgid = None
    _real_kill, _real_killpg = _os.kill, _os.killpg

    def _deny(msg):
        raise PermissionError("[host-guard] " + msg)

    def _kill(pid, sig):
        if sig != 0:
            if pid in (_main, 1, -1) or (pid < 0 and _main_pgid is not None and -pid == _main_pgid):
                _deny("os.kill ciblant le bot principal est interdit")
        return _real_kill(pid, sig)

    def _killpg(pgid, sig):
        if pgid in (1, _main_pgid):
            _deny("os.killpg ciblant le bot principal est interdit")
        return _real_killpg(pgid, sig)

    _os.kill, _os.killpg = _kill, _killpg
'''


def _ensure_guard_dir() -> None:
    try:
        os.makedirs(GUARD_DIR, exist_ok=True)
        path = os.path.join(GUARD_DIR, "sitecustomize.py")
        if not os.path.exists(path) or open(path, encoding="utf-8").read() != _SITECUSTOMIZE:
            with open(path, "w", encoding="utf-8") as f:
                f.write(_SITECUSTOMIZE)
    except OSError:
        pass


_ensure_guard_dir()


def build_env(env: dict, enforce: bool = True) -> dict:
    """Ajoute la protection d'exécution à l'environnement d'un script (non-admins)."""
    if not enforce:
        return env
    env = dict(env)
    env["BOT_MAIN_PID"] = str(os.getpid())
    env["PYTHONPATH"] = os.pathsep.join(p for p in (GUARD_DIR, env.get("PYTHONPATH")) if p)
    return env


def explain(verdict: Verdict) -> str:
    return "\n".join("• " + r for r in verdict.reasons)
