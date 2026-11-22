"""
Gestion des bibliothèques Python des scripts (partagée par le bot Telegram et
l'interface web) : détection des imports manquants (module ast) et dossier
d'installation à la demande (pip --target).
"""

import ast
import importlib
import importlib.util
import os
import sys

from keepalive import DATA_DIR

# Commande pip (modifiable, utile pour les tests)
PIP_CMD = [sys.executable, "-m", "pip"]
PIP_TIMEOUT_S = 300

# Nom du module à importer -> nom du paquet pip quand ils diffèrent
IMPORT_TO_PIP = {
    "cv2": "opencv-python-headless", "PIL": "pillow", "bs4": "beautifulsoup4",
    "yaml": "pyyaml", "sklearn": "scikit-learn", "skimage": "scikit-image",
    "telebot": "pyTelegramBotAPI", "telegram": "python-telegram-bot",
    "dotenv": "python-dotenv", "Crypto": "pycryptodome", "dateutil": "python-dateutil",
    "serial": "pyserial", "jwt": "pyjwt", "OpenSSL": "pyopenssl", "socks": "pysocks",
    "docx": "python-docx", "fitz": "pymupdf", "attr": "attrs",
}


# Bibliothèques installées à la demande : dans DATA_DIR/libs via `pip --target`.
# Fonctionne même si site-packages est en lecture seule (Choreo, conteneurs
# non-root) ou dans un virtualenv ; les scripts la voient grâce à PYTHONPATH.
LIBS_DIR = os.path.join(DATA_DIR, "libs")
try:
    os.makedirs(LIBS_DIR, exist_ok=True)
except OSError:
    pass


def _ensure_libs_on_path():
    """Rend visibles, dans le bot lui-même, les paquets installés après son démarrage."""
    if LIBS_DIR not in sys.path:
        sys.path.append(LIBS_DIR)
    importlib.invalidate_caches()


def _stdlib_names():
    """Noms des modules de la bibliothèque standard (compatible Python 3.9+)."""
    names = getattr(sys, "stdlib_module_names", None)  # Python 3.10+
    if names:
        return set(names)
    import sysconfig
    found = set(sys.builtin_module_names)
    stdlib = sysconfig.get_paths().get("stdlib")
    if stdlib and os.path.isdir(stdlib):
        for entry in os.listdir(stdlib):
            found.add(entry[:-3] if entry.endswith(".py") else entry.split(".")[0])
    return found


STDLIB_NAMES = _stdlib_names()


def find_missing_libraries(file_path):
    """Analyse les imports du script (module ast) et retourne les paquets pip manquants."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []  # l'erreur de syntaxe sera affichée à l'exécution

    _ensure_libs_on_path()
    local_dir = os.path.dirname(file_path)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])

    missing = []
    for mod in sorted(modules):
        if mod in STDLIB_NAMES:
            continue
        if os.path.exists(os.path.join(local_dir, mod + ".py")) or os.path.isdir(os.path.join(local_dir, mod)):
            continue  # module local du script
        try:
            if importlib.util.find_spec(mod) is not None:
                continue
        except (ImportError, ValueError, AttributeError):
            pass
        missing.append(IMPORT_TO_PIP.get(mod, mod))
    return missing
