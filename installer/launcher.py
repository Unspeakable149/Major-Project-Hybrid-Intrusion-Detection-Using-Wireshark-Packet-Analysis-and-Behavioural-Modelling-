"""Hybrid IDS — installed-app launcher.

Spawns the live backend silently, starts the Streamlit dashboard on a
free port, polls until the dashboard is reachable, opens the default
browser, and parks a tray icon for stop/exit control.

This file is the entry-point bundled by PyInstaller into HybridIDS.exe.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import pystray
from PIL import Image, ImageDraw


APP_NAME = "Hybrid IDS"
DEFAULT_PORT = 8501


def resource_path(relative: str) -> Path:
    """Resolve a bundled resource path for both source and PyInstaller-frozen runs."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / relative


def find_free_port(preferred: int = DEFAULT_PORT) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def hidden_popen(cmd: list, cwd: Path) -> subprocess.Popen:
    """Spawn a process with no visible console window."""
    creationflags = 0
    startupinfo = None
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        startupinfo=startupinfo,
    )


def wait_for_dashboard(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def make_tray_icon() -> Image.Image:
    """Generate a simple shield icon at runtime (avoids shipping a .ico file)."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield outline
    draw.polygon(
        [(32, 4), (60, 14), (58, 38), (32, 60), (6, 38), (4, 14)],
        fill=(28, 168, 88, 255),
        outline=(255, 255, 255, 255),
    )
    # Checkmark
    draw.line([(20, 32), (30, 42), (46, 24)], fill=(255, 255, 255, 255), width=4)
    return img


class IDSApp:
    def __init__(self) -> None:
        self.dashboard_dir = resource_path("Dashboard")
        self.port = find_free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.backend_proc: subprocess.Popen | None = None
        self.streamlit_proc: subprocess.Popen | None = None
        self.icon: pystray.Icon | None = None

    def start_backend(self) -> None:
        self.backend_proc = hidden_popen(
            [sys.executable, "live_backend.py"],
            cwd=self.dashboard_dir,
        )

    def start_streamlit(self) -> None:
        self.streamlit_proc = hidden_popen(
            [
                sys.executable, "-m", "streamlit", "run", "app.py",
                "--server.headless", "true",
                "--server.port", str(self.port),
                "--browser.gatherUsageStats", "false",
            ],
            cwd=self.dashboard_dir,
        )

    def open_dashboard(self, _icon=None, _item=None) -> None:
        webbrowser.open(self.url)

    def shutdown(self, _icon=None, _item=None) -> None:
        for proc in (self.streamlit_proc, self.backend_proc):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        if self.icon:
            self.icon.stop()

    def run(self) -> None:
        os.environ.setdefault("STREAMLIT_SERVER_FILE_WATCHER_TYPE", "none")
        self.start_backend()
        self.start_streamlit()

        def open_when_ready() -> None:
            if wait_for_dashboard(self.url):
                webbrowser.open(self.url)

        threading.Thread(target=open_when_ready, daemon=True).start()

        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", self.open_dashboard, default=True),
            pystray.MenuItem("Stop and Exit", self.shutdown),
        )
        self.icon = pystray.Icon(APP_NAME, make_tray_icon(), APP_NAME, menu)
        self.icon.run()


if __name__ == "__main__":
    IDSApp().run()
