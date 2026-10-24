#!/usr/bin/env python3
"""Mirraura desktop download overlay — full-screen translucent glass scene.

Runs on the Linux host (NOT inside Docker). It logs into the backend through
the dashboard nginx origin (the same /api paths the browser uses), watches
the Downloads folder for freshly-finished browser downloads, uploads each
one for shadow detonation, subscribes to /api/live, and drives the
pixel-art scene from scene.py:

    glass up -> device links to node -> honeypots spawn -> file detonates
    verdict Normal/Inconclusive   -> honeypots dissolve, file returns home
    verdict Suspicious/Compromised -> file locked in the shadow locker

ESC dismisses a running scene. Translucency needs a compositing window
manager (the default on modern Linux desktops); on Wayland you may need
QT_QPA_PLATFORM=xcb and a compositor that allows always-on-top windows.

Usage:
    python3 overlay.py              # normal operation
    python3 overlay.py --demo safe  # preview the animation with fake data
    python3 overlay.py --demo lock
"""

import json
import os
import signal
import sys
import threading
import time

import requests
import websocket

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5 import QtCore

from scene import Scene, Stage

SESSION_COOKIE = "mirraura_session"
# Backend marches to a 60s detonation budget; give the HTTP call a bit more.
UPLOAD_TIMEOUT_S = 75.0


def load_env_file(path):
    """Tiny .env parser — KEY=VALUE lines, '#' comments. No quoting fanciness."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip()] = val.strip()
    return values


def load_config():
    here = os.path.dirname(os.path.abspath(__file__))
    dot_env = load_env_file(os.path.join(here, "..", ".env"))
    cfg = {
        # Real environment beats .env, matching common .env tooling behavior.
        "dashboard_url": os.environ.get(
            "MIRRAURA_DASHBOARD_URL",
            dot_env.get("MIRRAURA_DASHBOARD_URL", "http://localhost:5173")),
        "downloads_dir": os.environ.get(
            "MIRRAURA_DOWNLOADS_DIR",
            dot_env.get("MIRRAURA_DOWNLOADS_DIR", "")) or os.path.expanduser("~/Downloads"),
        "admin_user": os.environ.get(
            "MIRRAURA_ADMIN_USER", dot_env.get("MIRRAURA_ADMIN_USER", "")),
        "admin_password": os.environ.get(
            "MIRRAURA_ADMIN_PASSWORD", dot_env.get("MIRRAURA_ADMIN_PASSWORD", "")),
    }
    cfg["downloads_dir"] = os.path.expanduser(cfg["downloads_dir"])
    return cfg


class BackendError(Exception):
    pass


class BackendClient:
    """Tiny authenticated client for the dashboard origin (nginx -> backend)."""

    def __init__(self, dashboard_url, username, password):
        self.base = dashboard_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.token = None

    @property
    def ws_url(self):
        return self.base.replace("https://", "wss://").replace("http://", "ws://") + "/api/live"

    def login(self):
        if not self.username or not self.password:
            raise BackendError("MIRRAURA_ADMIN_USER / MIRRAURA_ADMIN_PASSWORD not set")
        res = self.session.post(
            self.base + "/api/login",
            json={"username": self.username, "password": self.password},
            timeout=15)
        if res.status_code != 200:
            raise BackendError("login failed: HTTP %s (%s)" % (res.status_code, res.text[:120]))
        self.token = res.cookies.get(SESSION_COOKIE)
        if not self.token:
            raise BackendError("login succeeded but no %s cookie" % SESSION_COOKIE)
        return res.json()

    def cookie_header(self):
        if not self.token:
            raise BackendError("not logged in")
        return {"Cookie": "%s=%s" % (SESSION_COOKIE, self.token)}

    def upload(self, path):
        name = os.path.basename(path)
        if not self.token:
            self.login()
        with open(path, "rb") as fh:
            res = self.session.post(
                self.base + "/api/samples",
                files={"sample": (name, fh)},
                timeout=UPLOAD_TIMEOUT_S)
        if res.status_code != 200:
            raise BackendError("upload failed: HTTP %s (%s)" % (res.status_code, res.text[:160]))
        return res.json()


class Bridge(QObject):
    """Thread-safe signal relay from worker threads into the Qt main loop."""

    file_detected = pyqtSignal(str)
    upload_done = pyqtSignal(str, dict)
    upload_failed = pyqtSignal(str, str)
    live_message = pyqtSignal(dict)


_IGNORE_SUFFIXES = (".part", ".crdownload", ".tmp", ".download", ".swp", ",v")


def is_trackable_name(name):
    """A finished download file name the watcher should chase."""
    if name.startswith(".") or name.startswith("~$"):
        return False
    lower = name.lower()
    return not lower.endswith(_IGNORE_SUFFIXES)


def file_settled(last_size, size, stable_count):
    """A download is 'settled' once its size stops changing across polls."""
    return last_size == size and stable_count + 1 >= 2


class DownloadsWatcher(threading.Thread):
    """Polls the Downloads folder; each settled new file becomes one run.

    Polling (busybox-simple, cross-desktop) rather than inotify: browser
    downloads are identified only once their size stops changing, which is
    what makes *.part / *.crdownload files safe to ignore anyway.
    """

    POLL_INTERVAL = 1.2

    def __init__(self, client, bridge, watch_dir):
        super().__init__(daemon=True)
        self.client = client
        self.bridge = bridge
        self.watch_dir = watch_dir
        self.known = set()
        if os.path.isdir(watch_dir):
            self.known = {n for n in os.listdir(watch_dir)
                          if os.path.isfile(os.path.join(watch_dir, n))}
        else:
            print("[watcher] downloads dir missing: %s — only dashboard-triggered"
                  " scenes will fire" % watch_dir, file=sys.stderr)

    def run(self):
        tracking = {}  # name -> (last_size, stable_count)
        while True:
            time.sleep(self.POLL_INTERVAL)
            try:
                names = os.listdir(self.watch_dir)
            except OSError:
                continue
            for name in names:
                path = os.path.join(self.watch_dir, name)
                if name in self.known or not is_trackable_name(name) \
                        or not os.path.isfile(path):
                    continue
                size = 0
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size == 0:
                    continue
                last_size, count = tracking.get(name, (size, 0))
                if file_settled(last_size, size, count):
                    tracking.pop(name, None)
                    self.known.add(name)
                    threading.Thread(target=self._process, args=(path,),
                                     daemon=True).start()
                else:
                    tracking[name] = (size, count + 1)

    def _process(self, path):
        name = os.path.basename(path)
        self.bridge.file_detected.emit(name)
        time.sleep(0.4)  # let the glass rise before the request starts
        try:
            verdict = self.client.upload(path)
            self.bridge.upload_done.emit(name, verdict)
        except Exception as exc:  # backend down, auth failed, network blip
            self.bridge.upload_failed.emit(name, str(exc))


class LiveFeed(threading.Thread):
    """Long-lived /api/live WebSocket listener with re-login + reconnect."""

    def __init__(self, client, bridge):
        super().__init__(daemon=True)
        self.client = client
        self.bridge = bridge
        self.stopping = threading.Event()

    def stop(self):
        self.stopping.set()

    def run(self):
        backoff = 2.0
        while not self.stopping.is_set():
            try:
                self.client.login()
                ws = websocket.create_connection(
                    self.client.ws_url,
                    header=self.client.cookie_header())
                try:
                    while not self.stopping.is_set():
                        raw = ws.recv()
                        if not raw:
                            continue
                        try:
                            msg = json.loads(raw)
                        except ValueError:
                            continue  # malformed frame — drop it
                        self.bridge.live_message.emit(msg)
                finally:
                    ws.close()
                backoff = 2.0
            except Exception as exc:
                print("[live] feed offline (%s) — retrying in %.0fs"
                      % (exc, backoff), file=sys.stderr)
                self.stopping.wait(min(backoff, 30.0))
                backoff *= 2


class OverlayWindow(QWidget):
    """The translucent full-screen window; paints the Scene every frame."""

    FRAME_MS = 33  # ~30fps

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = Scene()
        self._armed = False  # does the next live/upload payload deserve a scene?
        self.setWindowFlags(
            QtCore.Qt.Window
            | QtCore.Qt.FramelessWindowHint
            | QtCore.Qt.WindowStaysOnTopHint
            | QtCore.Qt.Tool
            | QtCore.Qt.X11BypassWindowManagerHint
        )
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(self.FRAME_MS)

    # ------------------------------------------------------------- flow

    def show_ready_scene(self, filename):
        """Called when a new download/upload begins."""
        self.scene.set_filename(filename)
        self.scene.start()
        self._armed = True
        self.showFullScreen()
        self.raise_()
        self.activateWindow()

    def keyPressEvent(self, ev):
        if ev.key() == QtCore.Qt.Key_Escape:
            self.scene.abort()
            self.hide()
        else:
            super().keyPressEvent(ev)

    # ------------------------------------------------------------- slots

    def _tick(self):
        if self.scene.is_done():
            self.hide()
            self._armed = False
            return
        self.update()

    def paintEvent(self, _ev):
        painter = QPainter(self)
        self.scene.paint(painter, float(self.width()), float(self.height()))

    @QtCore.pyqtSlot(str)
    def on_file_detected(self, name):
        self.show_ready_scene(name)

    @QtCore.pyqtSlot(str, dict)
    def on_upload_done(self, name, verdict):
        self.scene.set_filename(name)
        self.scene.resolve(
            verdict.get("verdict") or "Inconclusive",
            verdict.get("confidence"),
            verdict.get("causal_chain") or [])

    @QtCore.pyqtSlot(str, str)
    def on_upload_failed(self, name, err):
        print("[overlay] upload failed for %s: %s" % (name, err), file=sys.stderr)
        self.scene.set_filename(name)
        self.scene.resolve("Inconclusive", 0.0,
                           ["upload failed — backend unreachable"])

    @QtCore.pyqtSlot(dict)
    def on_live_message(self, msg):
        mtype = msg.get("type")
        source = msg.get("source")
        data = msg.get("data") or {}

        if mtype == "verdict" and source == "sample":
            # A run finished. If the uploader already resolved the scene
            # (the POST response wins) this is a no-op; from a
            # dashboard-triggered upload nobody called resolve() yet, so
            # do it here. resolve() ignores double-calls itself.
            self.scene.set_filename(data.get("sample_filename") or
                                    self.scene._filename)
            self.scene.resolve(data.get("verdict"),
                               data.get("confidence"),
                               data.get("causal_chain"))
            return

        if mtype == "event" and source == "sample" and isinstance(data, dict):
            # First sample event with no scene running -> an upload was
            # started from the dashboard; open a scene for it.
            if not self._armed and not self.isVisible():
                self.show_ready_scene("dashboard upload")
            self.scene.sensor_event(data.get("event_type") or "")


# ------------------------------------------------------------------- demo

def run_demo(window, outcome):
    """Preview the animation end-to-end with fake data, no backend needed."""
    window.show_ready_scene("demo-eicar.bin")

    def detonation():
        for etype in ("process_spawn", "file_write", "network_connect",
                      "file_delete", "network_connect", "process_spawn"):
            window.scene.sensor_event(etype)
            time.sleep(0.35)

    def resolve():
        if outcome == "safe":
            window.scene.resolve("Normal", 0.0, ["no suspicious behavior observed"])
        else:
            window.scene.resolve("Compromised", 0.91,
                                 ["wrote to /etc/cron.d/persist"])

    threading.Thread(target=detonation, daemon=True).start()
    QTimer.singleShot(4000, resolve)


# -------------------------------------------------------------------- main

def main():
    cfg = load_config()
    demo = None
    if len(sys.argv) > 2 and sys.argv[1] == "--demo":
        demo = sys.argv[2].lower()
        if demo not in ("safe", "lock"):
            print("usage: overlay.py [--demo safe|lock]", file=sys.stderr)
            return 2

    app = QApplication(sys.argv)
    app.setApplicationName("Mirraura Overlay")
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Ctrl+C just works

    if demo:
        window = OverlayWindow()
        QTimer.singleShot(200, lambda: run_demo(window, demo))
        return app.exec_()

    client = BackendClient(cfg["dashboard_url"], cfg["admin_user"],
                           cfg["admin_password"])
    bridge = Bridge()
    window = OverlayWindow()

    bridge.file_detected.connect(window.on_file_detected)
    bridge.upload_done.connect(window.on_upload_done)
    bridge.upload_failed.connect(window.on_upload_failed)
    bridge.live_message.connect(window.on_live_message)

    LiveFeed(client, bridge).start()
    DownloadsWatcher(client, bridge, cfg["downloads_dir"]).start()

    print("[overlay] up — watching %s, dashboard %s" % (cfg["downloads_dir"],
                                                        cfg["dashboard_url"]))
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
