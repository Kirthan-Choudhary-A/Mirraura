# Mirraura

A shadow honeypot: it detonates uploaded files inside a throwaway,
network-isolated Docker container and scores their behavior for verdicts
like `Suspicious` or `Compromised`.

## Prerequisites

- Docker (with Docker Compose)

## Running it

```
cp .env.example .env
./setup.sh
```

Before running `./setup.sh`, set `MIRRAURA_ADMIN_USER` and
`MIRRAURA_ADMIN_PASSWORD` in `.env` (12+ characters, no default — the
script refuses to start otherwise).

Once the stack is up, the dashboard is at http://localhost:5173. Sign in
with the admin credentials from `.env`. There's no public sign-up; add more
accounts via an optional `MIRRAURA_USERS_PATH` JSON file (see
`.env.example`) if you need more than one user.

## Desktop download overlay

Mirraura ships a host-side desktop overlay (`overlay/`) that turns every
real download into a full-screen visual: a translucent glass layer over the
whole screen showing a pixel-art scene — your device linking to the shadow
node, honeypots spawning, the downloaded file detonating inside them — that
ends with the honeypots destroyed and the file returning (clean verdict) or
the file locked in a shadow locker (malicious verdict).

It runs on the host, not in Docker:

```bash
# with the Docker stack already running, in a graphical Linux session:
./overlay/run-overlay.sh

# preview the animation without a backend:
./overlay/run-overlay.sh --demo safe
./overlay/run-overlay.sh --demo lock
```

The daemon logs in with `MIRRAURA_ADMIN_USER`/`MIRRAURA_ADMIN_PASSWORD`,
reaches the backend through the dashboard origin (`MIRRAURA_DASHBOARD_URL`,
default `http://localhost:5173`), polls `MIRRAURA_DOWNLOADS_DIR`
(default `~/Downloads`) for files whose size has settled, uploads each one
for shadow detonation, and drives the animation from the same `/api/live`
WebSocket feed the dashboard uses. `.part`/`.crdownload` download stubs are
ignored. Press ESC to dismiss a running scene.

Translucency needs a compositing window manager (default on modern
desktops). On Wayland, run with `QT_QPA_PLATFORM=xcb` if the window does
not composite or draw above other windows.

## Demo samples

See `samples/` for files to upload through the dashboard. If you want to try
the EICAR test file specifically, read `samples/EICAR.md` first — Windows
Defender quarantines it on sight, so it needs to be regenerated manually.

## How it works

- `docs/concepts.md` — architecture and concepts overview
- `docs/superpowers/specs/2026-09-07-mirraura-design.md` — full design spec
