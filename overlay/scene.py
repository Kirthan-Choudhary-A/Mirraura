"""
Pixel-art "glass over the screen" scene engine for the Mirraura desktop
overlay.

The scene is a self-contained state machine that paints onto a full-screen
translucent Qt window. It is deliberately independent of how its inputs
arrive: callers (overlay.py) just push events in — download detected, live
sensor events, final verdict — and the scene animates through:

    device --(link)--> node --(spawn)--> honeypots --(detonate)-->
        verdict Normal/Inconclusive  -> honeypots destroyed, file returns
        verdict Suspicious/Compromised -> file locked in shadow locker

Coordinates live in a fixed 192x108 "virtual canvas" so the animation
proportions are identical on any screen; the caller scales the canvas to
the physical screen.

Stage timeline (seconds, stage-local):
  FADE_IN 0.0-0.8 glass fades in
  LINK    0.0-1.7 device token -> node link animation
  SPAWN   0.0-3.2 honeypot jars pop in staggered
  DETONATE open-ended; resolved by resolve() or the timeout, whichever
          comes first
  RELEASE 3.0s honeypots dissolve, chip returns home
  LOCK    3.4s file trapped in shadow locker
  after the finale the master alpha fades and the scene reports done()
"""

import math
import random

CANVAS_W = 192
CANVAS_H = 108

PAL = {
    "A": (87, 199, 255),   # cyan    - device screen, node frame, links
    "C": (38, 52, 78),     # slate   - dark frames, locker body
    "W": (232, 241, 255),  # white   - highlights, file page
    "M": (126, 240, 200),  # mint    - device accents
    "P": (167, 139, 250),  # violet  - device accents
    "Y": (255, 212, 92),   # gold    - honeypot jar, lock body
    "O": (255, 160, 60),   # amber   - honeypot core glow
    "K": (11, 18, 32),     # near black - keyhole
    "R": (255, 84, 112),   # red     - locked/alarm
    "G": (89, 255, 156),   # green   - safe
    "D": (18, 30, 52),     # deep    - screen base
}

SPRITE_DEVICE = [
    "......................",
    ".AAAAAAAAAAAAAAAAAA...",
    ".A................A...",
    ".A..WW..WW..WW....A...",
    ".A..WW..WW..WW....A...",
    ".A................A...",
    ".A....PP...M......A...",
    ".A................A...",
    ".AAAAAAAAAAAAAAAAAA...",
    "AAAAAAAAAAAAAAAAAAAAA.",
    "......................",
    "WWWWWWWWWWWWWWWWWWWW..",
]

SPRITE_NODE = [
    "CAAAAAAAAAAC",
    "CA.W....W.AC",
    "CA.........C",
    "CAAAAAAAAAAC",
    "CA...Y..W.AC",
    "CA.........C",
    "CAAAAAAAAAAC",
    "CA.W..G..W.C",
    "CA.........C",
    "CAAAAAAAAAAC",
    "CA..G...Y.AC",
    "CA.........C",
    "CAAAAAAAAAAC",
    "CCCCCCCCCCCC",
]

SPRITE_HONEYPOT = [
    "....YYYY....",
    "....YYYY....",
    "...Y....Y...",
    "..YY....YY..",
    ".YYYYYYYYYY.",
    ".Y........Y.",
    ".Y..O..O..Y.",
    ".Y..OOOO..Y.",
    ".Y........Y.",
    ".YYYYYYYYYY.",
    "..YYYYYYYY..",
]

SPRITE_FILE = [
    "CCCCCCCCCC",
    "C........C",
    "C..W....CC",
    "C..W...C.C",
    "C..W..C.C.",
    "C..W.C..C.",
    "C..W....C.",
    "C........C",
    "C......CC.",
    "C.....CC..",
    "CCCCCCCCCC",
]

SPRITE_LOCKER = [
    "CCCCCCCCCCCCCC",
    "C............C",
    "C.CC.CC.CC.C.C",
    "C.CC.CC.CC.C.C",
    "C............C",
    "CCCCCCCCCCCCC.",
    "C............C",
    "C.CC.CC.CC.C.C",
    "C.CC.CC.CC.C.C",
    "C............C",
    "CCCCCCCCCCCCC.",
    "C...RRRRRR...C",
    "C...RRRRRR...C",
    "C...R....R...C",
    "C...RRRRRR...C",
    "CCCCCCCCCCCCCC",
]

SPRITE_LOCK = [
    "..WWWWW..",
    ".W.....W.",
    ".W.....W.",
    "YYYYYYYYY",
    "YYYYYYYYY",
    "YYYYKYYYY",
    "YYYYKYYYY",
    "YYYYYYYYY",
    "YYYYYYYYY",
]

PIXEL_SCALE = 2  # sprite pixels per virtual-canvas unit

POS_DEVICE = (6, 74)          # top-left of the laptop sprite
POS_NODE = (64, 34)           # top-left of the node sprite
POS_HONEYPOTS = ((114, 26), (138, 26), (162, 26))
POS_LOCKER = (136, 62)

DEVICE_REACH = (POS_DEVICE[0] + 11 * PIXEL_SCALE, POS_DEVICE[1] + 7)
NODE_ANCHOR = (POS_NODE[0] + 6 * PIXEL_SCALE, POS_NODE[1] + 9 * PIXEL_SCALE)

# Sensor verdict timeout is 30s; keep a little grace before "Inconclusive".
RESOLVE_TIMEOUT_S = 35.0

_EVENT_LABELS = {
    "process_spawn": "spawn",
    "file_write": "write",
    "file_delete": "erase",
    "network_connect": "connect",
}


def _sprite_size(spr, scale=PIXEL_SCALE):
    return (len(spr[0]) * scale, len(spr) * scale)


class _Blob:
    """One honeypot jar on screen."""

    def __init__(self, idx):
        self.idx = idx
        self.spawned = False
        self.dissolve_start = None  # finale-local time its dissolution began
        self.flash_until = 0.0      # scene-clock time its flash fades away
        self.flash_label = ""
        self.glow_phase = random.random() * 6.28


class Stage:
    FADE_IN = "fadein"
    LINK = "link"
    SPAWN = "spawn"
    DETONATE = "detonate"
    RELEASE = "release"
    LOCK = "lock"
    DONE = "done"


class Scene:
    """State machine + painter. Push inputs in; call tick() once per frame."""

    def __init__(self):
        self.reset()
        self._filename = ""

    def reset(self):
        self.stage = Stage.FADE_IN
        self.t = 0.0           # stage-local clock (drifts past stage ends)
        self.master_t = 0.0    # scene-wide clock (glows, links, particles)
        self.master_alpha = 0.0
        self.blobs = [_Blob(i) for i in range(3)]
        self.particles = []
        self.flash_cursor = 0
        self.verdict_label = ""
        self.causal_first = ""
        self.det_started_at = 0.0   # master_t when DETONATE began
        self.resolved_outcome = None  # "released" | "locked" | None
        self.abort_requested = False
        self.done_notified = False
        self._rng = random.Random()

    # ------------------------------------------------------------- input

    def set_filename(self, name):
        self._filename = (name or "sample")[-44:]

    def start(self):
        """(Re)launch the whole sequence from the glass fade-in."""
        self.reset()

    def sensor_event(self, event_type, _detail=""):
        """Live detonation event -> flash one honeypot + spawn sparks."""
        if self.stage != Stage.DETONATE:
            return
        blob = self.blobs[self.flash_cursor % 3]
        self.flash_cursor += 1
        blob.flash_until = self.master_t + 0.55
        blob.flash_label = _EVENT_LABELS.get(event_type, event_type[:12])
        self._spawn_sparks(blob, PAL["O"], n=12)

    def resolve(self, verdict_label, _confidence=None, causal_chain=None):
        """Final verdict -> release (safe) or lock (malicious) finale."""
        if self.resolved_outcome is not None or self.abort_requested:
            return
        if self.stage == Stage.DONE:
            return
        label = (verdict_label or "Inconclusive").title()
        self.verdict_label = label
        chain = causal_chain or []
        self.causal_first = chain[0] if chain else ""
        safe = label in ("Normal", "Inconclusive")
        self.resolved_outcome = "released" if safe else "locked"
        self.stage = Stage.RELEASE if safe else Stage.LOCK
        self.t = 0.0
        for i, blob in enumerate(self.blobs):
            blob.dissolve_start = 0.55 + 0.4 * i if safe else None
        self._spawn_sparks(self.blobs[1],
                           PAL["G"] if safe else PAL["R"], n=26)

    def abort(self):
        """Operator pressed ESC — tear the scene down immediately."""
        self.abort_requested = True
        self.stage = Stage.DONE
        self.done_notified = True

    # -------------------------------------------------------------- tick

    def tick(self, dt):
        dt = min(dt, 0.1)
        self.master_t += dt
        if self.stage == Stage.DONE:
            return
        self.t += dt

        if self.master_t > 0.25 and self.master_alpha < 1.0 \
                and not self._fading_out():
            self.master_alpha = min(1.0, self.master_alpha + dt * 2.6)

        if self.stage == Stage.FADE_IN:
            if self.t > 0.8:
                self._goto(Stage.LINK)
        elif self.stage == Stage.LINK:
            if self.t > 1.7:
                self._goto(Stage.SPAWN)
        elif self.stage == Stage.SPAWN:
            for blob in self.blobs:
                if not blob.spawned and self.t > 0.35 + 0.55 * blob.idx:
                    blob.spawned = True
                    self._spawn_sparks(blob, PAL["Y"], n=10)
            if self.t > 3.2:
                self._goto(Stage.DETONATE)
        elif self.stage == Stage.DETONATE:
            if (self.resolved_outcome is None
                    and self.master_t - self.det_started_at > RESOLVE_TIMEOUT_S):
                self.resolve("Inconclusive", 0.0,
                             ["no verdict arrived before timeout"])

        # particle physics
        alive = []
        for p in self.particles:
            p["life"] -= dt
            if p["life"] <= 0:
                continue
            p["x"] += p["vx"] * dt
            p["y"] += p["vy"] * dt
            p["vy"] += 26.0 * dt  # pixel confetti falls
            alive.append(p)
        self.particles = alive

        if self._fading_out():
            self.master_alpha = max(0.0, self.master_alpha - dt * 1.3)
            if self.master_alpha <= 0.0:
                self.stage = Stage.DONE
                self.done_notified = True

    def _fading_out(self):
        """True once a resolved finale has passed its showcase time and is
        fading the scene back out."""
        if self.stage not in (Stage.RELEASE, Stage.LOCK):
            return False
        total = 3.0 if self.stage == Stage.RELEASE else 3.4
        return self.t > total

    def _goto(self, stage):
        self.stage = stage
        self.t = 0.0
        if stage == Stage.DETONATE:
            self.det_started_at = self.master_t

    def is_done(self):
        return self.stage == Stage.DONE and self.done_notified

    def _spawn_sparks(self, blob, color, n):
        cx, cy = POS_HONEYPOTS[blob.idx]
        cx += 6
        cy += 6
        for _ in range(n):
            ang = self._rng.random() * 6.283
            speed = 6.0 + self._rng.random() * 16.0
            self.particles.append({
                "x": cx, "y": cy,
                "vx": math.cos(ang) * speed,
                "vy": math.sin(ang) * speed - 8.0,
                "life": 0.55 + self._rng.random() * 0.5,
                "color": color,
            })

    # -------------------------------------------------------------- paint

    def paint(self, painter, w, h):
        s = min(w / CANVAS_W, h / CANVAS_H)
        ox = (w - CANVAS_W * s) / 2.0
        oy = (h - CANVAS_H * s) / 2.0
        ramp = min(1.0, self.master_t / 0.6)
        glass_alpha = min(ramp, max(self.master_alpha, 0.0))
        if glass_alpha <= 0.01 and self.master_alpha <= 0.01:
            return

        self._paint_glass(painter, w, h, s, glass_alpha)
        if self.stage == Stage.FADE_IN and self.master_alpha <= 0.02:
            return

        painter.setOpacity(self.master_alpha)
        self._paint_banner(painter, w, s)

        # links: device->node always; node->honeypots once they exist;
        # both wither away during the release finale (except the return leg).
        show_links = self.stage != Stage.LINK
        if self.resolved_outcome == "released":
            show_links = self.t < 1.2
        self._paint_pixel_line(painter, s, DEVICE_REACH, NODE_ANCHOR,
                               phase=self.master_t)
        if show_links:
            for c in POS_HONEYPOTS:
                self._paint_pixel_line(
                    painter, s, NODE_ANCHOR,
                    (c[0] + 6, c[1] + 6),
                    phase=self.master_t + 3.0 + c[1] * 0.1)

        green = self.resolved_outcome == "released" and self.t > 1.4
        self._paint_sprite(painter, SPRITE_DEVICE, POS_DEVICE[0],
                           POS_DEVICE[1], s, led_override="G" if green else None)
        node_led = "G" if green else None
        self._paint_node(painter, s, node_led)

        for blob, c in zip(self.blobs, POS_HONEYPOTS):
            self._paint_honeypot(painter, blob, c[0], c[1], s)

        self._paint_file_chip(painter, s)

        if self.resolved_outcome == "locked":
            self._paint_locker_finale(painter, s)

        if self.stage != Stage.FADE_IN:
            name = ("incoming: " + self._filename) if self._filename \
                else "incoming sample"
            self._draw_text(painter, name, ox + 6 * s, oy + 102 * s,
                            size=max(10, int(s * 1.5)),
                            color=(200, 225, 245),
                            alpha=0.8 * self.master_alpha)

        self._paint_particles(painter, s)
        painter.setOpacity(1.0)

    # -------------------------------------------------------- sub-painters

    def _paint_glass(self, painter, w, h, s, alpha):
        from PyQt5.QtCore import QPointF, QLinearGradient, QRadialGradient
        from PyQt5.QtGui import QColor, QPolygonF

        painter.setOpacity(alpha)
        band_h = max(2.0, h * 0.28)
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0.0, QColor(8, 14, 28, int(196 * alpha)))
        grad.setColorAt(0.45, QColor(6, 12, 24, int(212 * alpha)))
        grad.setColorAt(1.0, QColor(10, 22, 40, int(228 * alpha)))
        painter.fillRect(0, 0, w, h, grad)

        # diagonal sheen streaks — the "glass" read
        for i, src_x in enumerate((-0.35, 0.45, 1.1)):
            top_from = QPointF(w * (src_x + 0.35), 0)
            poly = QPolygonF()
            sw = w * 0.30
            poly << QPointF(w * (src_x - 0.06), h)
            poly << QPointF(w * (src_x - 0.06) + sw, h)
            poly << QPointF(w * (src_x - 0.06) + sw + w * 0.10, 0)
            poly << QPointF(w * (src_x - 0.06) + w * 0.10, 0)
            a = 14 + (6 if i == 1 else 0)
            painter.setOpacity(alpha * a / 255.0)
            painter.fillPath(poly, QColor(190, 235, 255))
        painter.setOpacity(alpha)

        # faint pixel grid — sells "pixel world behind glass"
        step = s * 6
        if step >= 3:
            painter.setOpacity(alpha * 0.05)
            painter.fillRect(0, 0, w, h, QColor(87, 199, 255))
            painter.setPen(QColor(87, 199, 255, int(alpha * 26)))
            x = 0
            while x < w:
                painter.drawLine(int(x), 0, int(x), int(h))
                x += step
            y = 0
            while y < h:
                painter.drawLine(0, int(y), int(w), int(y))
                y += step

        # vignette
        painter.setOpacity(alpha)
        vgrad = QRadialGradient(w / 2.0, h * 0.42, max(w, h) * 0.75)
        vgrad.setColorAt(0.0, QColor(0, 0, 0, 0))
        vgrad.setColorAt(1.0, QColor(0, 0, 12, int(120 * alpha)))
        painter.fillRect(0, 0, w, h, vgrad)

        if self.resolved_outcome == "locked":
            pulse = 0.5 + 0.5 * math.sin(self.t * 5.0)
            painter.setOpacity(alpha * (0.5 + 0.5 * pulse) * 0.35)
            painter.fillRect(0, 0, w, h, QColor(255, 84, 112))

    def _paint_banner(self, painter, w, s):
        if self.stage in (Stage.FADE_IN, Stage.LINK):
            text = "LINKING DEVICE TO SHADOW NODE ..."
        elif self.stage == Stage.SPAWN:
            text = "SPAWNING SHADOW HONEYPOTS ..."
        elif self.stage == Stage.DETONATE:
            text = "DETONATING DOWNLOADED FILE - OBSERVING ..."
        elif self.stage == Stage.RELEASE:
            text = ("VERDICT: %s - HONEYPOTS DESTROYED, FILE RELEASED"
                    % (self.verdict_label or "NORMAL"))
        elif self.stage == Stage.LOCK:
            text = ("VERDICT: %s - LOCKED IN SHADOW LOCKER"
                    % (self.verdict_label or "MALICIOUS"))
        else:
            text = ""
        if not text:
            return
        col = PAL["A"]
        if self.stage == Stage.RELEASE:
            col = PAL["G"]
        elif self.stage == Stage.LOCK:
            col = PAL["R"]
        self._draw_text(painter, text, w / 2.0, 26, size=max(12, int(s * 1.7)),
                        color=col, alpha=0.95 * self.master_alpha,
                        center=True)
        if self.stage in (Stage.RELEASE, Stage.LOCK) and self.causal_first:
            self._draw_text(painter, self.causal_first, w / 2.0, 40,
                            size=max(9, int(s * 1.15)),
                            color=(210, 228, 245), alpha=0.75 * self.master_alpha,
                            center=True)

    def _paint_pixel_line(self, painter, s, p0, p1, phase=0.0):
        from PyQt5.QtGui import QColor

        x0, y0 = p0
        x1, y1 = p1
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy) or 1.0
        ux, uy = dx / length, dy / length
        spacing = 5.0
        offset = (phase * 14.0) % spacing
        painter.setOpacity(self.master_alpha * 0.75)
        d = offset
        while d < length - 2.0:
            cx = x0 + ux * d
            cy = y0 + uy * d
            self._paint_unit_rect(painter, cx - 1, cy - 1, 2, 2, s, PAL["A"])
            d += spacing

    def _paint_sprite(self, painter, spr, x, y, s, scale=PIXEL_SCALE, led_override=None):
        for j, row in enumerate(spr):
            for i, ch in enumerate(row):
                if ch == "." or ch not in PAL:
                    continue
                col = PAL[led_override] if (led_override and ch in "AG") else PAL[ch]
                self._paint_unit_rect(painter, x + i * scale, y + j * scale,
                                      scale, scale, s, col)

    def _paint_node(self, painter, s, led_override=None):
        x, y = POS_NODE
        self._paint_sprite(painter, SPRITE_NODE, x, y, s, led_override=led_override)
        bob = math.sin(self.master_t * 2.0) * 0.8
        self._draw_text(painter, "shadow node", x, y + 8 * PIXEL_SCALE + 2 + bob,
                        size=max(9, int(s * 1.1)), color=(150, 205, 235),
                        alpha=0.7 * self.master_alpha)

    def _paint_honeypot(self, painter, blob, x, y, s):
        if self.stage in (Stage.FADE_IN, Stage.LINK):
            return
        if not blob.spawned and self.stage != Stage.SPAWN:
            return
        dissolve = 0.0
        if blob.dissolve_start is not None and self.t > blob.dissolve_start:
            dissolve = min(1.0, (self.t - blob.dissolve_start) / 1.0)
        if dissolve >= 1.0:
            return
        bob = math.sin(self.master_t * 2.0 + blob.glow_phase) * 0.7 * (
            0.0 if dissolve > 0 else 1.0)
        yy = y + bob
        if dissolve > 0:
            self._paint_sprite_dissolving(painter, SPRITE_HONEYPOT, x, yy,
                                          s, dissolve)
            return
        self._paint_sprite(painter, SPRITE_HONEYPOT, x, yy, s)
        if self.stage == Stage.DETONATE:
            now = self.master_t
            if now < blob.flash_until:
                k = (blob.flash_until - now) / 0.55
                painter.setOpacity(self.master_alpha * k * 0.8)
                self._paint_unit_rect(painter, x + 1, yy + 1, 10, 10, s,
                                      PAL["W"])
                painter.setOpacity(self.master_alpha)
                self._draw_text(painter, blob.flash_label, x + 6, yy + 14.5,
                                size=max(9, int(s * 1.05)),
                                color=PAL["Y"], alpha=k * self.master_alpha,
                                center=True)
            else:
                glow = 0.5 + 0.5 * math.sin(self.master_t * 3.0 + blob.glow_phase)
                painter.setOpacity(self.master_alpha * 0.25 + 0.15 * glow)
                self._paint_unit_rect(painter, x + 4, yy + 5, 4, 3, s,
                                      PAL["O"])

    def _paint_sprite_dissolving(self, painter, spr, x, y, s, progress):
        for j, row in enumerate(spr):
            for i, ch in enumerate(row):
                if ch == "." or ch not in PAL:
                    continue
                key = hash((i, j, x))
                cellp = (key % 100) / 100.0
                if progress >= cellp:
                    continue
                self._paint_unit_rect(painter, x + i * PIXEL_SCALE,
                                      y + j * PIXEL_SCALE, PIXEL_SCALE,
                                      PIXEL_SCALE, s, PAL[ch])

    def _file_chip_pos(self):
        c = POS_HONEYPOTS[1]
        honeypot_center = (c[0] + 6, c[1] + 6)
        node_center = NODE_ANCHOR
        device_center = DEVICE_REACH
        if self.stage in (Stage.FADE_IN, Stage.LINK):
            return None
        if self.stage == Stage.SPAWN:
            k = min(1.0, max(0.0, (self.t - 0.3) / 1.9))
            k = k * k * (3 - 2 * k)  # smoothstep
            return (device_center[0] + (node_center[0] - device_center[0]) * k,
                    device_center[1] + (node_center[1] - device_center[1]) * k)
        if self.stage == Stage.DETONATE:
            if self.t < 0.8:
                k = self.t / 0.8
                k = k * k * (3 - 2 * k)
                return (node_center[0] + (honeypot_center[0] - node_center[0]) * k,
                        node_center[1] + (honeypot_center[1] - node_center[1]) * k)
            bob = math.sin(self.master_t * 4.0) * 0.5
            return (honeypot_center[0], honeypot_center[1] + bob)
        if self.resolved_outcome == "released":
            if self.t < 1.6:
                return (honeypot_center[0], honeypot_center[1])
            if self.t < 2.9:
                k = min(1.0, (self.t - 1.6) / 1.2)
                k = k * k * (3 - 2 * k)
                mid = (node_center[0],
                       node_center[1])
                via = ((honeypot_center[0] + mid[0]) / 2.0,
                       (honeypot_center[1] + mid[1]) / 2.0)
                to_dev = min(1.0, max(0.0, (self.t - 2.0) / 0.9))
                via2 = (via[0] + (device_center[0] - via[0]) * to_dev,
                        via[1] + (device_center[1] - via[1]) * to_dev)
                return (mid[0] + (via2[0] - mid[0]) * k,
                        mid[1] + (via2[1] - mid[1]) * k)
            return device_center
        if self.resolved_outcome == "locked":
            if self.t < 1.4:
                return (honeypot_center[0], honeypot_center[1])
            if self.t < 2.4:
                k = min(1.0, (self.t - 1.4) / 1.0)
                k = k * k * (3 - 2 * k)
                lc = (POS_LOCKER[0] + 7, POS_LOCKER[1] + 10)
                return (honeypot_center[0] + (lc[0] - honeypot_center[0]) * k,
                        honeypot_center[1] + (lc[1] - honeypot_center[1]) * k)
            lc = (POS_LOCKER[0] + 7, POS_LOCKER[1] + 10)
            return (lc[0], lc[1] - 1.5)
        return (honeypot_center[0], honeypot_center[1])

    def _paint_file_chip(self, painter, s):
        pos = self._file_chip_pos()
        if pos is None:
            return
        bob = math.sin(self.master_t * 3.2) * 0.6
        alpha = self.master_alpha
        if self.resolved_outcome == "released" and self.t >= 2.7:
            blink = 0.5 + 0.5 * math.sin(self.t * 8.0)
            alpha *= 0.4 + 0.6 * blink
        painter.setOpacity(alpha)
        scale = 1  # chip drawn at 1 unit per sprite pixel (small)
        self._paint_sprite(painter, SPRITE_FILE, pos[0] - 5, pos[1] - 5 - bob,
                           s, scale=scale)

    def _paint_locker_finale(self, painter, s):
        if self.t < 0.25:
            return
        alpha = min(1.0, (self.t - 0.25) / 0.5) * self.master_alpha
        rise = (1.0 - min(1.0, (self.t - 0.25) / 0.6)) * 6.0
        x, y = POS_LOCKER
        painter.setOpacity(alpha)
        self._paint_sprite(painter, SPRITE_LOCKER, x, y + rise, s)
        if self.t > 2.55:
            lk = min(1.0, (self.t - 2.55) / 0.35)
            drop = (1.0 - lk) * 5.0
            self._paint_sprite(painter, SPRITE_LOCK,
                               x + 2.5, y + rise + 5.0 + drop, s)
        self._draw_text(painter, "SHADOW LOCKER", x + 7, y + rise - 2.5,
                        size=max(9, int(s * 1.1)), color=PAL["R"],
                        alpha=0.85 * self.master_alpha, center=True)

    def _paint_particles(self, painter, s):
        for p in self.particles:
            a = min(1.0, p["life"] / 0.4)
            painter.setOpacity(self.master_alpha * a)
            self._paint_unit_rect(painter, p["x"], p["y"], 1.4, 1.4, s,
                                  p["color"])
        painter.setOpacity(self.master_alpha)

    # ------------------------------------------------------------ helpers

    def _paint_unit_rect(self, painter, ux, uy, uw, uh, s, color):
        from PyQt5.QtGui import QColor
        painter.fillRect(
            int(round(ux * s)), int(round(uy * s)),
            max(1, int(round(uw * s))), max(1, int(round(uh * s))),
            QColor(color[0], color[1], color[2]))

    def _draw_text(self, painter, text, x, y, size, color, alpha,
                   center=False):
        from PyQt5.QtGui import QColor, QFont
        from PyQt5.QtCore import QRectF

        font = QFont("DejaVu Sans Mono,Consolas,monospace")
        font.setBold(True)
        font.setPixelSize(max(9, int(size)))
        painter.setFont(font)
        painter.setOpacity(max(0.0, min(1.0, alpha)))
        painter.setPen(QColor(color[0], color[1], color[2]))
        rect_h = size * 2.2
        if center:
            painter.drawText(QRectF(x - 3000, y - size, 6000, rect_h),
                             int(0x0084), text)  # AlignHCenter | AlignVCenter
        else:
            painter.drawText(QRectF(x, y - size, 2600, rect_h),
                             int(0x0004), text)  # AlignVCenter
