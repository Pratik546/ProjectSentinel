"""Refresh requirements-lock.txt using pip-tools when it is installed."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
try:
    subprocess.run([sys.executable, "-m", "piptools", "compile", "requirements.txt", "--output-file", "requirements-lock.txt"], cwd=root, check=True)
except (subprocess.CalledProcessError, FileNotFoundError):
    raise SystemExit("pip-tools is required: python -m pip install pip-tools")
