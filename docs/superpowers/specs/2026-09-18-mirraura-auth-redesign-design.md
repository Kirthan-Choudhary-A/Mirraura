# Mirraura — Bug Fixes, Login, and Frontend Redesign (Design)

Three-part initiative, executed in this order because each part depends on
groundwork from the one before it (the redesign's login page needs the auth
backend; same-origin `/api` URLs need nginx from Part 2):

1. Fix existing bugs (frontend + backend).
2. Add a user login in front of the whole app.
3. Redesign the frontend so it looks like a polished security-operations
   console.

Repo conventions apply throughout: no "prototype"/"Day N" framing anywhere,
minimum code that works, reuse before adding a dependency, and every new
language/library/tool gets an entry in `docs/concepts.md` in the same change
that introduces it.

---

## Part 1 — Bug fixes

### Frontend

1. **Event feed clears on any click.** `App.tsx` wraps `UploadPanel` in
   `<div onClickCapture={handleNewRun}>`, so clicking the file picker wipes
   the feed. Remove the wrapper; clear events only when an upload actually
   starts.
2. **Upload and monitoring streams are mixed.** Live events and verdicts
   from the 10s monitoring loop land in the same feed and overwrite the
   upload verdict. Add a `source: "sample" | "monitor"` field to every
   WebSocket message (backend `hub.go` broadcast sites + `LiveMessage`
   type) and render the two paths separately.
3. **WebSocket never reconnects.** Add reconnect with exponential backoff
   (1s → 30s cap), guard `JSON.parse` with try/catch, and expose connection
   state (`connecting | live | offline`) to the UI.
4. **`VITE_BACKEND_URL` is baked in at build time**, so runtime overrides do
   nothing. Fixed by serving frontend and API from the same origin (Part 2's
   nginx reverse proxy) and using relative `/api` URLs; delete
   `VITE_BACKEND_URL`. **This bug's fix ships in Part 2**, not Part 1 — Part
   1 only removes the env var usage it safely can without nginx in place.
5. **Swallowed errors.** `fetchVerdicts` and `fetchMonitorStatus` don't
   check `res.ok`; `AuditLogTable` turns failures into an empty table;
   `App` ignores monitor-status failures. Every fetch must check `res.ok`,
   and every panel must show a real error state.
6. **Unbounded event array.** Cap the feed at the last 500 events.
7. `index.html` title is `frontend`; replace with `Mirraura`. Delete
   leftover Vite-template CSS (`#social`, `.counter`, centered `#root`, 56px
   `h1`) and unused `public/icons.svg` if nothing references it.

### Backend / verdict engine

1. **Sandbox hardening** in `backend/dockermanager.go` for the detonation
   container's `HostConfig`: `Memory` (e.g. 256MB), `PidsLimit` (e.g. 128),
   `CapDrop: ["ALL"]` (add back only what `strace` needs — test it, likely
   `SYS_PTRACE`), `SecurityOpt: ["no-new-privileges"]`, `ReadonlyRootfs:
   true` with a small `Tmpfs` for the working dir, and a hard execution
   timeout that surfaces as an `Inconclusive` verdict with a causal-chain
   reason, not a hung request. Add/adjust tests in `dockermanager_test.go`.
2. **CORS `*`** in `main.go`: remove it — with same-origin serving it's
   unnecessary.
3. **WebSocket origin check:** `gorilla/websocket`'s `CheckOrigin` must
   reject cross-origin upgrades.
4. **`trained_scorer.py` can never emit `Normal`** (sigmoid never reaches
   exactly 0.0). Give it its own `verdict_from_score` with a low threshold
   (e.g. `< 0.1` → Normal), add a test, and update the caveat paragraph in
   `docs/concepts.md`.
5. Document the Docker-socket mount risk in `docs/concepts.md` (backend
   compromise = host compromise) — no code change required.

---

## Part 2 — User login

### Behavior

- The app opens on a **login page**. Nothing else — no dashboard data, no
  WebSocket — is reachable until signed in.
- **No public sign-up** (it's a security tool). Users are seeded from env:
  `MIRRAURA_ADMIN_USER` / `MIRRAURA_ADMIN_PASSWORD` in `.env.example` (no
  default password; `setup.sh` refuses to start if it's unset or shorter
  than 12 chars).
- Two roles: `admin` (can approve/reject hashes and reconnect an isolated
  endpoint) and `analyst` (read-only + upload). Optional extra users via a
  `users.json` of `{username, bcrypt_hash, role}`; include a tiny `go run
  ./cmd/hashpw` helper or document `htpasswd -bnBC 10`.
- Logout button in the header. Session expires after 8 hours of
  inactivity.

### Backend implementation (Go)

- `POST /api/login` (JSON `{username, password}`), `POST /api/logout`,
  `GET /api/me` → `{username, role}`.
- Passwords checked with `golang.org/x/crypto/bcrypt` (constant-time; same
  generic "Invalid username or password" error for unknown user and wrong
  password).
- Session: random 32-byte token (`crypto/rand`) in an in-memory map, sent
  as cookie `mirraura_session` with `HttpOnly`, `SameSite=Strict`,
  `Path=/`, `Secure` when served over HTTPS. Mark the in-memory store with
  a `// ponytail:` comment (sessions lost on restart; move to a store if
  multi-instance).
- Auth middleware wraps every `/api/*` route except `/api/login` and
  `/api/health`, **including `/api/live`** (WebSocket upgrade checks the
  cookie). Role check on hash approve/reject and `/api/monitor/reconnect`
  → 403 for analysts.
- Login rate limit: 5 failed attempts per IP per 15 minutes → 429.
- **Record who did it:** the username goes into the audit log for uploads,
  hash approvals/rejections, and reconnects (pass it to the verdict engine
  and store it as `actor`). The human-approval gate now has an actual named
  human — call this out in `docs/concepts.md`.
- Tests: login success/failure, middleware blocks unauthenticated
  requests, analyst gets 403 on approve, WebSocket rejected without
  cookie.

### Serving (fixes bug 4 too)

- Replace `serve` in `frontend/Dockerfile` with `nginx:alpine`: serves
  `dist/` with SPA fallback and reverse-proxies `/api/` (including
  WebSocket upgrade headers) to `backend:8080`. Only the frontend port is
  published in `docker-compose.yml`; the backend and verdict engine stop
  publishing ports to the host.
- Add nginx security headers: `Content-Security-Policy` (self only),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`.

### Frontend

- On load call `/api/me`: 401 → login page, 200 → dashboard. Any 401 later
  (expired session) returns to login with "Your session expired" message.
- No router library needed — a single `user | null` state switch.

---

## Part 3 — Frontend redesign (the "immaculate" part)

### Design direction

A dark-first, precise **security operations console** — think Linear /
Vercel dashboard polish applied to a threat-detection tool. Calm,
dense-but-breathing, high contrast where it matters (verdicts, isolation)
and quiet everywhere else. Not a generic admin template, no gradient-blob
hero, no purple-on-white startup look. Every pixel intentional. Light mode
supported, dark is the default hero.

### Dependencies allowed (and only these)

- `lucide-react` — icons.
- `@fontsource-variable/inter` and `@fontsource-variable/jetbrains-mono` —
  self-hosted fonts (no Google Fonts CDN; the tool should work offline and
  the CSP stays `self`).
- Everything else: plain CSS (CSS variables, grid, container queries) and
  React. No Tailwind, no component library, no animation library. Add both
  to `docs/concepts.md`.

### Design tokens (`index.css`, rewritten from scratch)

- Background layers: `--bg` near-black with a hint of blue (`#0b0d12`),
  `--surface` (`#12151c`), `--surface-2` (`#181c25`), `--border`
  (`#232834`), hairline 1px borders instead of heavy shadows.
- Text: `--text` (`#e6e8ee`), `--text-muted` (`#8b93a7`), `--text-faint`
  (`#5b6376`).
- One accent: cool cyan/teal (`#3dd6c6`) for focus rings, links, "live"
  state.
- Verdict semantic colors, each with a solid + 12%-alpha background
  variant: Normal `#34d399`, Suspicious `#fbbf24`, Compromised `#f43f5e`,
  Inconclusive `#94a3b8`.
- Spacing scale 4/8/12/16/24/32/48; radius 8px (cards 12px); type scale
  12/13/14/16/20/28/40 with Inter, tabular numbers for all figures,
  JetBrains Mono for hashes, paths, IPs, PIDs.
- Matching light theme under `prefers-color-scheme: light`, plus a manual
  theme toggle in the header persisted to `localStorage` (wrapped in
  try/catch).
- Motion: 150–200ms ease-out for hovers/state changes, all disabled under
  `prefers-reduced-motion`.

### Login page

- Full-viewport split layout on desktop: left 55% a dark panel with a
  subtle animated background (slow-moving CSS grid/dot pattern or faint
  scanning line — pure CSS, reduced-motion safe), the Mirraura wordmark + a
  one-line tagline ("Detonate in the shadow. Protect the real.") and three
  small feature bullets with icons (Isolated detonation · Explainable
  verdicts · Tamper-evident audit). Right 45%: a centered card with
  username, password (show/hide toggle), "Sign in" button with loading
  spinner, inline error under the form, caps-lock warning.
- Mobile: single column, card only with the wordmark above it.
- Proper `<label>`s, `autocomplete="username"` / `"current-password"`,
  focus on username on load, Enter submits, button disabled while
  submitting.
- Design a simple wordmark/logo: an SVG mark (e.g. two offset mirrored
  shapes suggesting a shadow copy) + "Mirraura" in Inter semibold. Use it
  as the favicon too.

### Dashboard layout

```
┌ Header: [logo] Mirraura   ● Live            Monitor: ● Connected   [theme] [user ▾ role · Sign out] ┐
├ Isolation banner (only when isolated): full-width, rose, pulsing dot, "Reconnect" (admin only)      ┤
├──────────────────────────────┬──────────────────────────────────────────────────────────────────────┤
│ Detonate a sample (card)     │ Live telemetry (card, tabs: Shadow run | Endpoint monitor)           │
│  drag-and-drop zone          │  filter chips: Process · File · Network                             │
│  file name, size, SHA-256    │  virtual-feel scrolling list, newest at bottom, auto-scroll unless   │
│  run progress stepper:       │  user scrolled up ("↓ N new events" pill)                           │
│  Upload→Isolate→Detonate→    │  each row: type icon, mono detail, relative time,                   │
│  Observe→Score→Teardown      │  rule-triggering rows highlighted with the rule name                │
├──────────────────────────────┤                                                                      │
│ Verdict (card)               │                                                                      │
│  big badge w/ icon + label,  │                                                                      │
│  confidence ring or bar,     │                                                                      │
│  causal chain as timeline    │                                                                      │
│  with rule weight per step   │                                                                      │
├──────────────────────────────┴──────────────────────────────────────────────────────────────────────┤
│ Tabs: Audit log  |  Hash approvals (count badge)                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- Max content width ~1440px, 24px gutters; collapses to a single column
  below 960px, 16px gutters on phones, no horizontal page scroll at 375px
  (tables scroll inside their card).
- Header stat strip under the header (optional but recommended): Samples
  analyzed · Compromised · Pending approvals · Chain status — tabular
  numbers, derived from existing API data, no new endpoints.

### Component details

- **Upload:** native drag-and-drop (`dragover`/`drop`) + click-to-browse,
  computes SHA-256 client-side with `crypto.subtle.digest` and shows it
  before upload. While running, show the step list animating through the
  stages (driven by incoming WebSocket events for that run). Clear, human
  error messages.
- **Verdict:** badge never relies on color alone (icon + text). Confidence
  shown as a number and a bar/ring. Causal chain as a vertical timeline;
  empty chain → "No suspicious behavior observed." Show sample hash (mono,
  truncated middle, click to copy with a toast), timestamp, and the source
  (sample vs monitor). Empty state: an illustration-free, elegant
  placeholder explaining what will appear here. (Builds on the
  `sample_filename`/report fields already threaded through the pipeline —
  see the detonation-report change that landed just before this spec.)
- **Event feed:** icons per type (process / file / network), color-coded
  left rule, monospace details, relative timestamps with full ISO on
  hover. Rows that match a scoring rule (sensitive-path write, non-standard
  port, child process) get a small tag naming the rule.
- **Audit log:** sticky header, zebra-free (hairline row dividers),
  relative time + tooltip, verdict pills, actor column, copy-able hashes,
  client-side pagination (25/page), search box filtering by
  hash/verdict/actor. **Chain integrity indicator**: recompute or fetch
  chain verification and show "✓ Chain intact · N entries" or a rose "✗
  Chain broken at entry N" — this is the log's headline feature, make it
  visible.
- **Hash approvals:** count badge on the tab; each pending row has Approve
  / Reject; both open a confirmation dialog (native `<dialog>`) showing the
  full hash and label; analysts see the list read-only. Manual submit form
  validates `^[a-f0-9]{64}$` before sending, with inline field errors.
- **Isolation banner:** unmistakable but not ugly — rose surface,
  shield-alert icon, pulsing dot, timestamp of isolation, Reconnect button
  (admin) with confirm dialog.
- **Toasts:** one tiny self-written toast component for
  copy/approve/reconnect/errors (no library).
- **Loading states:** skeleton shimmer blocks for cards/tables on first
  load, not spinners everywhere.
- **Empty and error states** designed for every panel.

### Code structure

- Keep the existing component split; add `LoginPage.tsx`, `Header.tsx`,
  `StatStrip.tsx`, and small shared pieces only where reused 2+ times (e.g.
  `Badge`, `Card`, `CopyHash`, `Toast`, `ConfirmDialog`). Co-locate CSS as
  plain `.css` files per component or CSS modules (Vite supports them
  natively). No inline `style={{}}` for static styles.
- All colors through the tokens — no hex literals in components.
- `api.ts`: one `request()` helper that checks `res.ok`, parses JSON, and
  throws a typed error with status (so 401 → logout, 403 → "Admins only"
  toast). Use relative URLs.

### Accessibility (non-negotiable)

Semantic landmarks (`header`, `main`, `section` with headings), visible
focus rings (accent), all icon-only buttons have `aria-label`, verdict/feed
updates announced via an `aria-live="polite"` region, tabs with correct
ARIA roles and arrow-key navigation, contrast ≥ 4.5:1 for text in both
themes, full keyboard operability including dialogs (Esc closes, focus
returns).

---

## Definition of done

- `npm run build`, `npm run lint`, `npm test` pass in `frontend/`; `go test
  ./...` in `backend/`; `pytest` in `verdict-engine/`.
- Vitest tests for: the `request()` helper (401/403/ok paths), SHA-256 hash
  validation regex, and the WebSocket message reducer (source separation,
  500-event cap).
- `./setup.sh` brings the stack up; open http://localhost:5173 → login page
  → sign in as admin → upload each file in `samples/` and confirm: steps
  animate, feed fills, correct verdict appears, audit log updates with
  your username as actor, chain shows intact. Sign in as an analyst and
  confirm approve/reconnect are hidden/forbidden.
- Check the UI at 1440px, 1024px, and 375px widths in both themes; no
  horizontal scroll, no overlapping text.
- `docs/concepts.md` updated: authentication/session model, roles, nginx
  same-origin serving, bcrypt, lucide-react, fontsource, sandbox
  hardening, trained-scorer threshold fix. `README.md` updated with the
  new `.env` variables and login step.
- Commit in logical steps (bugs → backend auth → nginx serving → design
  system → login page → dashboard components → docs), each commit building
  and passing tests.
