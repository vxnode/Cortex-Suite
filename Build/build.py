import os
import subprocess
import sys

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BUILD_DIR, ".."))

SCRIPT_PATH = os.path.join(PROJECT_ROOT, "cortex_suite.py")
ICON_PATH = os.path.join(BUILD_DIR, "icon.ico")
HIDDEN_IMPORTS_FILE = os.path.join(BUILD_DIR, "hiddenimports.txt")

hidden_imports = []
if os.path.exists(HIDDEN_IMPORTS_FILE):
    with open(HIDDEN_IMPORTS_FILE, "r", encoding="utf-8") as f:
        hidden_imports = [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]

cmd = [
    sys.executable,
    "-m", "PyInstaller",
    "--onefile",
    "--name", "Cortex",
    "--icon", ICON_PATH,
    "--clean",
    "--noconfirm",
]

for module in hidden_imports:
    cmd += ["--hidden-import", module]

cmd.append(SCRIPT_PATH)

subprocess.run(cmd, check=True)
