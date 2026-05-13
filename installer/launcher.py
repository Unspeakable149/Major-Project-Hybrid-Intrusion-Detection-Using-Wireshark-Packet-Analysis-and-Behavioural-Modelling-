"""Hybrid IDS — installed-app launcher.

Process layout (single OS process, no subprocesses):
    main thread       Streamlit web server (bootstrap.run; signal handlers
                      installed correctly here).
    daemon thread     Backend capture/classification loop (live_backend.main).
    daemon thread     System-tray icon (pystray).
    daemon thread     Edge / Chrome app-mode window opened once dashboard
                      becomes reachable.

A sentinel env var hard-stops the launcher if a child process is ever
spawned in error (no subprocess spawn paths remain, but the guard stays as
defense-in-depth).
"""

import logging
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path


APP_NAME = "Hybrid IDS"
DEFAULT_PORT = 8501
SENTINEL_VAR = "HYBRID_IDS_LAUNCHER_ACTIVE"

if os.environ.get(SENTINEL_VAR) == "1":
    sys.exit(0)
os.environ[SENTINEL_VAR] = "1"


def _log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = Path(base) / "Hybrid IDS"
    d.mkdir(parents=True, exist_ok=True)
    return d


LOG_PATH = _log_dir() / "launcher.log"
logging.basicConfig(
    filename=str(LOG_PATH),
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("HybridIDS")
log.info("=== launcher startup ===")
log.info("frozen=%s  executable=%s", getattr(sys, "frozen", False), sys.executable)


# Frozen windowed builds have no usable stdout/stderr. Many libraries
# (streamlit, joblib, sklearn) write to stderr at import or runtime — a
# failed write tears the process down. Route everything to the log file.
class _StreamToLog:
    def __init__(self, level: int) -> None:
        self.level = level
        self._buf = ""

    def write(self, msg: str) -> int:
        if not isinstance(msg, str):
            return 0
        self._buf += msg
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line:
                logging.log(self.level, "[stdio] %s", line)
        return len(msg)

    def flush(self) -> None:
        if self._buf:
            logging.log(self.level, "[stdio] %s", self._buf)
            self._buf = ""

    def isatty(self) -> bool:
        return False


if getattr(sys, "frozen", False):
    sys.stdout = _StreamToLog(logging.INFO)
    sys.stderr = _StreamToLog(logging.WARNING)


def find_free_port(preferred: int = DEFAULT_PORT) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def wait_for_dashboard(url: str, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def make_tray_icon():
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon(
        [(32, 4), (60, 14), (58, 38), (32, 60), (6, 38), (4, 14)],
        fill=(28, 168, 88, 255),
        outline=(255, 255, 255, 255),
    )
    draw.line([(20, 32), (30, 42), (46, 24)], fill=(255, 255, 255, 255), width=4)
    return img


EDGE_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]
CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def open_app_window(url: str) -> None:
    log.info("opening dashboard window for %s", url)
    nowindow = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    for browser in (_first_existing(EDGE_CANDIDATES), _first_existing(CHROME_CANDIDATES)):
        if not browser:
            continue
        try:
            subprocess.Popen(
                [browser, f"--app={url}", "--window-size=1400,900"],
                close_fds=True, creationflags=nowindow,
            )
            log.info("launched %s in app mode", os.path.basename(browser))
            return
        except Exception as e:
            log.exception("%s launch failed: %s", browser, e)

    try:
        subprocess.Popen(["explorer.exe", url], close_fds=True, creationflags=nowindow)
        log.info("fell back to explorer.exe")
    except Exception as e:
        log.exception("all open methods failed: %s", e)


# Module-level state shared between the backend, tray, and main threads.
_STATE = {
    "dashboard_dir": None,
    "port": None,
    "url": None,
    "icon": None,
}


def resource_path(relative: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        base = Path(__file__).resolve().parent.parent
    return base / relative


def run_backend_thread() -> None:
    try:
        log.info("backend: importing live_backend")
        import live_backend  # noqa: F401 — Dashboard dir on sys.path
        log.info("backend: starting main()")
        live_backend.main()
    except SystemExit:
        pass
    except Exception:
        log.exception("backend crashed")


def run_tray_thread() -> None:
    try:
        import pystray
        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", lambda *_: open_app_window(_STATE["url"]), default=True),
            pystray.MenuItem("Stop and Exit", lambda *_: shutdown()),
        )
        icon = pystray.Icon(APP_NAME, make_tray_icon(), APP_NAME, menu)
        _STATE["icon"] = icon
        log.info("tray: starting icon loop")
        icon.run()
    except Exception:
        log.exception("tray crashed")


def run_open_when_ready_thread() -> None:
    url = _STATE["url"]
    log.info("waiter: polling %s", url)
    if wait_for_dashboard(url):
        log.info("waiter: dashboard reachable, opening window")
        open_app_window(url)
    else:
        log.error("waiter: dashboard never became reachable")


def shutdown() -> None:
    log.info("shutdown requested")
    if _STATE.get("icon"):
        try:
            _STATE["icon"].stop()
        except Exception:
            pass
    os._exit(0)


def main() -> None:
    dashboard_dir = resource_path("Dashboard")
    if not dashboard_dir.exists():
        log.error("Dashboard bundle missing: %s", dashboard_dir)
        sys.exit(1)

    sys.path.insert(0, str(dashboard_dir))
    os.chdir(dashboard_dir)
    log.info("cwd=%s", dashboard_dir)

    port = find_free_port()
    url = f"http://127.0.0.1:{port}"
    _STATE.update(dashboard_dir=dashboard_dir, port=port, url=url)
    log.info("selected port=%d url=%s", port, url)

    # Start the supporting threads BEFORE blocking on Streamlit.
    threading.Thread(target=run_backend_thread, daemon=True, name="ids-backend").start()
    threading.Thread(target=run_tray_thread,     daemon=True, name="ids-tray").start()
    threading.Thread(target=run_open_when_ready_thread, daemon=True, name="ids-waiter").start()

    # Streamlit's bootstrap installs signal handlers — must run on the main
    # thread on Windows. This call blocks forever.
    log.info("main: importing streamlit.web.bootstrap")
    from streamlit.web import bootstrap
    os.environ.setdefault("STREAMLIT_SERVER_FILE_WATCHER_TYPE", "none")
    os.environ.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")
    flag_options = {
        "server.port": port,
        "server.headless": True,
        "server.fileWatcherType": "none",
        "browser.gatherUsageStats": False,
        "global.developmentMode": False,
    }
    bootstrap.load_config_options(flag_options=flag_options)
    log.info("main: bootstrap.run(port=%d)", port)
    try:
        bootstrap.run(str(dashboard_dir / "app.py"), False, [], flag_options)
    except Exception:
        log.exception("streamlit bootstrap crashed")
        sys.exit(1)


if __name__ == "__main__":
    main()
