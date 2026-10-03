import os
import platform
import sys
from pathlib import Path


AGENT_NAME = "Process Guardian Agent"
AGENT_VERSION = "3.1.0"

HOST = "127.0.0.1"

# 5050 avoids the macOS AirPlay Receiver conflict on port 5000.
PORT = int(os.getenv("PROCESS_GUARDIAN_PORT", "5050"))


def data_dir():
    custom = os.getenv("PROCESS_GUARDIAN_DATA_DIR")

    if custom:
        path = Path(custom).expanduser()
    elif platform.system() == "Windows":
        base = os.getenv("APPDATA") or str(Path.home())
        path = Path(base) / "ProcessGuardian"
    elif platform.system() == "Darwin":
        path = Path.home() / "Library" / "Application Support" / "ProcessGuardian"
    else:
        base = os.getenv("XDG_DATA_HOME")
        if base:
            path = Path(base) / "process-guardian"
        else:
            path = Path.home() / ".local" / "share" / "process-guardian"

    path.mkdir(parents=True, exist_ok=True)
    return path


def agent_info():
    return {
        "name": AGENT_NAME,
        "version": AGENT_VERSION,
        "hostname": platform.node(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "pid": os.getpid(),
        "host": HOST,
        "port": PORT,
        "local_only": True,
        "data_directory": str(data_dir()),
    }