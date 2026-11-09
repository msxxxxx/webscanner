"""Одноразовая установка dirsearch и nuclei.
Запуск: .venv/bin/python -m scripts.install_scanners
"""
import os
import platform
import subprocess
import sys
import zipfile

from app.config import settings

DIRSEARCH_REPO = "https://github.com/maurosoria/dirsearch.git"
NUCLEI_VERSION = "3.3.5"


def install_dirsearch() -> bool:
    venv_python = os.path.join(settings.DIRSEARCH_DIR, "venv", "bin", "python3")
    if os.path.exists(settings.DIRSEARCH_PATH):
        print(f"✅ dirsearch already installed: {settings.DIRSEARCH_DIR}")
        return True

    print("📥 Cloning dirsearch...")
    r = subprocess.run(
        ["git", "clone", DIRSEARCH_REPO, settings.DIRSEARCH_DIR],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        print(f"❌ git clone failed: {r.stderr}")
        return False

    print("🔧 Creating venv...")
    r = subprocess.run(
        ["python3", "-m", "venv", os.path.join(settings.DIRSEARCH_DIR, "venv")],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        print(f"❌ venv creation failed: {r.stderr}")
        return False

    print("📦 Installing requirements...")
    r = subprocess.run(
        [venv_python, "-m", "pip", "install", "-r",
         os.path.join(settings.DIRSEARCH_DIR, "requirements.txt")],
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        print(f"❌ pip install failed: {r.stderr}")
        return False

    print("✅ dirsearch installed")
    return True


def install_nuclei() -> bool:
    if os.path.exists(settings.NUCLEI_BIN):
        print(f"✅ nuclei already installed: {settings.NUCLEI_BIN}")
        return True

    from shutil import which
    if which("nuclei"):
        print(f"✅ nuclei found in PATH: {which('nuclei')}")
        return True

    arch = "amd64" if platform.machine() in ("x86_64", "AMD64") else "arm64"
    url = (
        f"https://github.com/projectdiscovery/nuclei/releases/download/"
        f"v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_linux_{arch}.zip"
    )
    zip_path = "/tmp/nuclei.zip"
    print(f"📥 Downloading nuclei from {url}")

    try:
        subprocess.run(["wget", "-q", url, "-O", zip_path], check=True, timeout=300)
        with zipfile.ZipFile(zip_path) as z:
            z.extract("nuclei", "/tmp/")
        subprocess.run(["chmod", "+x", "/tmp/nuclei"], check=True)
        subprocess.run(["sudo", "mv", "/tmp/nuclei", settings.NUCLEI_BIN], check=True)
        subprocess.run([settings.NUCLEI_BIN, "-update-templates", "-silent"], timeout=300)
        print(f"✅ nuclei installed: {settings.NUCLEI_BIN}")
        return True
    except Exception as e:
        print(f"❌ nuclei install failed: {e}")
        return False
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


if __name__ == "__main__":
    ok1 = install_dirsearch()
    ok2 = install_nuclei()
    sys.exit(0 if (ok1 and ok2) else 1)