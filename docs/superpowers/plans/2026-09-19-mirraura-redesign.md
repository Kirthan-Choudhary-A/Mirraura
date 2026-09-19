# Mirraura Frontend Redesign (Part 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **A note on this plan's shape, different from Part 1 and Part 2's plans:**
> Parts 1 and 2 were correctness/feature work, so their plans gave exact,
> copy-pasteable code for every line. Part 3 is visual design work — the
> `frontend-design` skill's own process (plan → review against brief for
> genericness → build → critique) is the right process for that, not
> line-by-line prescription. So this plan gives **exact, non-negotiable
> values** for anything the design brief pins down (colors, type scale,
> spacing, the dependency list, prop interfaces other tasks depend on) and
> **clear requirements + constraints** — not full JSX — for the creative
> component work, trusting the implementer's craft within those
> constraints. Every visual task's review step includes a design critique
> (screenshots, checked against genericness tells) in addition to the
> usual spec-compliance and code-quality review.

**Goal:** Redesign the frontend into a distinctive, accessible, dark-first
security-operations console, matching the Part 3 design brief, without
touching the backend/verdict-engine contracts Parts 1–2 already built
(except one small, additive read endpoint for audit-chain verification).

**Architecture:** A ground-up `index.css` token rewrite (Task 1) underpins
everything else. A handful of new shared primitives (Task 2) get reused
across the larger component rewrites (Tasks 5–10). One new backend
read-only endpoint (Task 3) exposes the audit log's existing hash-chain
verification for the dashboard's "chain intact" indicator. Everything
assembles in `App.tsx` (Task 11).

**Tech Stack:** React + TypeScript (existing), `lucide-react` (icons, new),
`@fontsource-variable/inter` + `@fontsource-variable/jetbrains-mono`
(self-hosted variable fonts, new), plain CSS (custom properties, grid,
container queries) — no Tailwind, no component library, no animation
library. Go stdlib (existing) for the one new backend route. Python/FastAPI
(existing) for the one new verdict-engine route.

**Spec:** `docs/superpowers/specs/2026-09-18-mirraura-auth-redesign-design.md`
(Part 3 — Frontend redesign)

## Design Plan (frontend-design skill, first pass)

**Color** (the brief pins these exactly — not a generic default, a
client-specified palette; used verbatim):
`--bg #0b0d12`, `--surface #12151c`, `--surface-2 #181c25`,
`--border #232834`, `--text #e6e8ee`, `--text-muted #8b93a7`,
`--text-faint #5b6376`, `--accent #3dd6c6` (cyan/teal — the one accent).
Verdict severity: Normal `#34d399`, Suspicious `#fbbf24`, Compromised
`#f43f5e`, Inconclusive `#94a3b8`, each with a 12%-alpha background tint.

**Type:** Inter Variable for UI text (a humanist grotesk that stays crisp
at small sizes and has real tabular figures — the "precise ops console"
feel without leaning on a coded/monospace-everywhere look). JetBrains Mono
Variable reserved strictly for hashes, paths, IPs, PIDs, ports, and
timestamps — a face designed for scanning code, which is exactly the skill
a security analyst uses to spot a suspicious path or a weird port at a
glance. Scale: 12/13/14/16/20/28/40, tabular-nums on every numeric value.

**Layout:** Left-aligned, dense grid (not centered/marketing-style), 1440px
max content width. The brief's own ASCII wireframe is the layout —
followed exactly, not reinterpreted.

**Principles (this is where this design earns its own identity, not just
the client's pinned tokens):**
1. The live event trace is the visual hero of the working view, not the
   upload card — everything else stays quieter so the trace reads as "the
   thing actually happening right now."
2. One motion vocabulary, tied only to real events (a trace row arriving, a
   verdict flash, the detonation spinner, a toast appearing) — never
   decorative on-scroll or on-hover animation beyond ordinary focus/press
   feedback.
3. Verdict-severity color appears *only* on verdict-bearing surfaces
   (badges, the chain-integrity indicator, the isolation banner) — never as
   generic UI chrome — so red/amber/green keep meaning instead of becoming
   decoration.
4. A typographic rule, not just a style: monospace numbers are
   *identifiers* to verify (hash, PID, port); proportional tabular numbers
   are *measurements* (confidence %, counts). The face itself tells you
   which kind of number you're looking at.
5. One elevation step. `--surface` vs `--surface-2` plus a 1px `--border`
   is the entire depth system — no shadows, no card-soup, matching the
   Linear/Vercel reference the brief names.

**Genericness check (the skill's required self-review):** trait #2 on the
skill's tell-list ("near-black background with a single bright accent") is
literally what's being built here — but the brief specifies this palette
explicitly and by exact hex value, so per the skill's own rule ("where the
brief pins down a visual direction, follow it exactly, including when it
asks for one of these looks") this is a client choice, not a generic
default reached for out of habit. What *is* this design's own choice,
where the brief leaves room: the login page's animated background (a
single slow-drifting 1px scanline in the accent color, ~8s traverse, ~15%
peak opacity, paused entirely under `prefers-reduced-motion` — chosen over
a generic dot-grid because a sweeping scan line reads specifically as "a
detonation chamber being watched," which is what this product actually
does, not decoration for its own sake); the wordmark (two overlapping
offset rounded shapes suggesting a duplicated "shadow" silhouette, not a
generic geometric monogram); and the typographic number rule in Principle
4, which is a deliberate house rule rather than "monospace everywhere" or
"monospace nowhere." No cream/serif/terracotta, no zero-radius broadsheet
(the brief specifies 8/12px radius), no repeated identical-shadow card
grid (one elevation step, hairline borders only), no tracked-out ALL-CAPS
eyebrows anywhere in this plan's component requirements.

## Global Constraints

- No "prototype"/"Day N" framing in code, comments, docs, or commit
  messages.
- Dependencies: `lucide-react`, `@fontsource-variable/inter`,
  `@fontsource-variable/jetbrains-mono` — and nothing else. No Tailwind, no
  component library, no animation library, no state-management library.
  Both new deps get a `docs/concepts.md` entry in the same task that adds
  them (Task 1).
- All colors through the CSS custom properties defined in Task 1 — no hex
  literals in any component file from Task 2 onward.
- No inline `style={{}}` for anything static (dynamic per-instance values
  like a computed severity color as a CSS variable, as `VerdictPanel`
  already does, remain fine).
- Every icon-only button has an `aria-label`. Every dialog is a native
  `<dialog>` element (Esc closes, focus returns to the trigger on close).
  Tabs use correct ARIA roles (`tablist`/`tab`/`tabpanel`) and arrow-key
  navigation. Verdict/feed updates go through an `aria-live="polite"`
  region. Contrast ≥ 4.5:1 for text in both themes — check this against
  the exact hex values above, not just "looks fine."
- `prefers-reduced-motion` disables all non-essential motion (the login
  scanline, hover transitions can shorten to near-zero, but state changes
  that convey information — like a verdict appearing — still happen, just
  without the animated flourish).
- This plan builds directly on top of Part 2's branch (`mirraura-login`,
  currently an open, unmerged PR stacked on Part 1's) — every file this
  plan touches already reflects Parts 1 and 2's changes (session cookies,
  `request()`/`ApiError` in `api.ts`, the `user` gate in `App.tsx`, actor
  fields in audit records). Do not re-derive those changes or assume
  earlier shapes.
- No test-rendering harness exists in this repo (no `@testing-library/react`,
  no `jsdom` in `vite.config.ts`) and none should be added — visual/behavioral
  verification for component tasks is manual (screenshots via a headless
  browser, the same approach the Part 1 dashboard redesign already used
  successfully), not a new test dependency. Pure-logic additions (the
  SHA-256 hex helper, the hash-regex validator) DO get ordinary Vitest unit
  tests, same as every other pure function in `api.ts`.

---

### Task 1: Design tokens, dependencies, theme toggle

**Files:**
- Create: `frontend/src/theme.ts`
- Modify: `frontend/package.json` (via `npm install`)
- Modify: `frontend/src/index.css` (rewritten from scratch)
- Modify: `frontend/src/main.tsx` (import the self-hosted font packages)
- Modify: `docs/concepts.md`

**Interfaces:**
- Produces: the full CSS custom-property token set below, available to
  every later task. `frontend/src/theme.ts` exports `type Theme = "dark" |
  "light"`, `function getStoredTheme(): Theme` (reads `localStorage`,
  wrapped in try/catch, defaults to `"dark"` if unset/unavailable), and
  `function setStoredTheme(t: Theme): void` (writes it, also try/catch
  wrapped). These get consumed by Task 4's `Header` (the toggle button).

- [ ] **Step 1: Install the two new dependencies**

Run: `cd frontend && npm install lucide-react @fontsource-variable/inter @fontsource-variable/jetbrains-mono`

- [ ] **Step 2: Import the self-hosted fonts**

In `frontend/src/main.tsx`, add these two imports at the top (before the
existing `import "./index.css"` if present, or add one if the file doesn't
currently import the stylesheet directly — check the current file first):

```ts
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
```

- [ ] **Step 3: Rewrite `frontend/src/index.css`'s token block**

Replace the file's `:root { ... }` block (and any other global reset rules
at the top of the file) with:

```css
:root {
  --bg: #0b0d12;
  --surface: #12151c;
  --surface-2: #181c25;
  --border: #232834;

  --text: #e6e8ee;
  --text-muted: #8b93a7;
  --text-faint: #5b6376;

  --accent: #3dd6c6;
  --accent-bg: color-mix(in srgb, var(--accent) 12%, transparent);

  --sev-normal: #34d399;
  --sev-normal-bg: color-mix(in srgb, var(--sev-normal) 12%, transparent);
  --sev-suspicious: #fbbf24;
  --sev-suspicious-bg: color-mix(in srgb, var(--sev-suspicious) 12%, transparent);
  --sev-compromised: #f43f5e;
  --sev-compromised-bg: color-mix(in srgb, var(--sev-compromised) 12%, transparent);
  --sev-inconclusive: #94a3b8;
  --sev-inconclusive-bg: color-mix(in srgb, var(--sev-inconclusive) 12%, transparent);

  --font-sans: "Inter Variable", system-ui, "Segoe UI", sans-serif;
  --font-mono: "JetBrains Mono Variable", ui-monospace, Consolas, monospace;

  --fs-1: 12px;
  --fs-2: 13px;
  --fs-3: 14px;
  --fs-4: 16px;
  --fs-5: 20px;
  --fs-6: 28px;
  --fs-7: 40px;

  --sp-1: 4px;
  --sp-2: 8px;
  --sp-3: 12px;
  --sp-4: 16px;
  --sp-5: 24px;
  --sp-6: 32px;
  --sp-7: 48px;

  --radius: 8px;
  --radius-card: 12px;

  --motion-fast: 150ms ease-out;
  --motion-base: 200ms ease-out;

  color-scheme: dark;
  font: var(--fs-4)/1.5 var(--font-sans);
  color: var(--text-muted);
  background: var(--bg);
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

:root[data-theme="light"] {
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-2: #eef0f3;
  --border: #dde1e7;
  --text: #12151c;
  --text-muted: #4b5565;
  --text-faint: #7c8798;
  color-scheme: light;
}

@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    --bg: #f6f7f9;
    --surface: #ffffff;
    --surface-2: #eef0f3;
    --border: #dde1e7;
    --text: #12151c;
    --text-muted: #4b5565;
    --text-faint: #7c8798;
    color-scheme: light;
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text-muted);
}

#root {
  min-height: 100svh;
}

h1, h2, h3 {
  font-family: var(--font-sans);
  font-weight: 600;
  color: var(--text);
  margin: 0 0 var(--sp-2);
}

.mono {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

*:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
  }
}
```

Read the rest of the current `index.css` file below this point (panel,
button, table, upload, causal-list, hash-form, monitor-banner, error-text,
etc. — everything the existing components reference) and **do not delete
it in this task** — later tasks (2 and onward) will replace each of those
rules as they rewrite the component that owns them. For this task, only
the token block and the base reset above are in scope. If any of the
*old* rules reference a variable name this task just removed (e.g. the old
`--bg`/`--ink`/`--ink-muted`/`--ember` names from the Part 1 palette), leave
them as broken/stale for now — the component tasks that own those rules
will replace them. Note in your report which old variable names you found
still referenced, so later tasks know what's pending.

Add the light-theme attribute toggle target used by Task 4: the selector
`:root[data-theme="light"]` above is what `Header`'s theme toggle will set
via `document.documentElement.dataset.theme = "light" | "dark"`.

- [ ] **Step 4: Create `frontend/src/theme.ts`**

```ts
export type Theme = "dark" | "light";

const STORAGE_KEY = "mirraura-theme";

export function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function setStoredTheme(theme: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // localStorage unavailable (private mode, blocked) — theme just
    // won't persist across reloads, which is a harmless degradation.
  }
}
```

- [ ] **Step 5: Update `docs/concepts.md`**

Add two bullets under "Tools & libraries — what and why":

```markdown
**lucide-react** — A tree-shakeable icon set as React components (not an
icon font or an SVG-sprite build step). Used for every icon in the
redesigned dashboard (event types, verdict badges, the isolation banner,
theme toggle) instead of hand-drawn inline SVGs, since a consistent
stroke-width icon family reads as one visual system rather than a pile of
one-off shapes.

**@fontsource-variable/inter & @fontsource-variable/jetbrains-mono** —
Self-hosted variable-font packages (the font files ship in the built
bundle, not fetched from a CDN at runtime). Chosen over the Google Fonts
CDN links Part 1 shipped with, specifically so the dashboard works fully
offline and so the CSP introduced in Part 2 (`default-src 'self'`) never
has to carve out an exception for a third-party font host.
```

- [ ] **Step 6: Build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm run build`
Expected: builds clean (the app will look visually broken/inconsistent
until later tasks replace the remaining old rules — that's expected and
fine for this task).

- [ ] **Step 7: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/src/main.tsx frontend/src/index.css frontend/src/theme.ts docs/concepts.md
git commit -m "feat: rewrite design tokens, add lucide-react and self-hosted fonts"
```

---

### Task 2: Shared primitives — Badge, Card, Toast, ConfirmDialog, CopyHash

**Files:**
- Create: `frontend/src/components/Badge.tsx` + `Badge.css`
- Create: `frontend/src/components/Card.tsx` + `Card.css`
- Create: `frontend/src/components/Toast.tsx` + `Toast.css`
- Create: `frontend/src/components/ConfirmDialog.tsx` + `ConfirmDialog.css`
- Create: `frontend/src/components/CopyHash.tsx` + `CopyHash.css`
- Create: `frontend/src/components/CopyHash.test.ts` (or co-locate in
  `api.test.ts` if the truncation helper lives there — implementer's call,
  see Step 5)

**Interfaces (later tasks depend on these exactly):**
- `<Badge tone="normal" | "suspicious" | "compromised" | "inconclusive" | "neutral" icon={ReactNode} children={ReactNode} />` — renders the icon +
  text pill using the matching `--sev-*`/`--sev-*-bg` tokens for the four
  verdict tones, and `--border`/`--text-muted` for `"neutral"`. Never
  color-only: icon + text always both present.
- `<Card title={string} action={ReactNode?}>{children}</Card>` — the one
  panel/card shell every other task's component renders inside, using
  `--surface`, `--border`, `--radius-card`. Replaces the current bare
  `<div className="panel">` pattern.
- `useToast()` — a hook returning `{ push: (message: string, tone?: "info" | "success" | "error") => void }`, plus a `<ToastHost />` component
  rendered once near the root of `App.tsx` that actually displays queued
  toasts (auto-dismiss after ~4s, `aria-live="polite"`, stacked
  bottom-right, dismissible by click). Implement via React context: a
  `ToastProvider` wrapping the app (or a simple module-level event-bus if
  you judge that cleaner for a single-provider app like this one — your
  call, document which you chose and why in your report).
- `<ConfirmDialog open={boolean} title={string} description={ReactNode} confirmLabel={string} onConfirm={() => void} onCancel={() => void} />` —
  wraps a native `<dialog>`, calls `.showModal()`/`.close()` via a ref
  effect keyed on `open`, Esc closes and calls `onCancel`, focus returns to
  whatever triggered it on close (native `<dialog>` does this by default —
  verify it, don't fight it).
- `<CopyHash hash={string} label?={string} />` — renders the hash
  truncated-middle (e.g. `a1b2c3…f9e8d7`) in `.mono`, click-to-copy via
  `navigator.clipboard.writeText`, pushes a toast ("Copied to clipboard")
  on success via `useToast()`. Full untruncated hash available via
  `title=` attribute for hover, and via a visually-hidden element for
  screen readers (don't rely on `title` alone for accessibility). Export
  the truncation function itself, e.g. `truncateMiddle(s: string, keep: number = 6): string`, so it's unit-testable.

- [ ] **Step 1: Implement `Badge`**

Build `Badge.tsx`/`Badge.css` per the interface above. Icons come from
`lucide-react` — pick one clear icon per tone that a security analyst
would recognize at a glance without reading the label (e.g. a check-circle
family for Normal, an alert-triangle family for Suspicious, an
octagon-alert/shield-alert family for Compromised, a help-circle/circle-dashed
family for Inconclusive) — your call on the exact icon names available in
the installed `lucide-react` version, just keep the semantic pairing
consistent everywhere Badge is used later.

- [ ] **Step 2: Implement `Card`**

Build `Card.tsx`/`Card.css`. `<h2>` for the title (matches the existing
heading hierarchy every panel already uses), an optional `action` slot
rendered top-right of the header row (e.g. for a tab's count badge or a
Card-level action button later tasks need).

- [ ] **Step 3: Implement `Toast`/`useToast`/`ToastHost`**

Build per the interface above. No external state library — a small
context + `useState`/`useEffect` (or the module-event-bus alternative) is
enough for this app's size.

- [ ] **Step 4: Implement `ConfirmDialog`**

Build per the interface above, using a native `<dialog>` element (not a
hand-rolled modal with a manual backdrop/focus-trap — the platform feature
already does this correctly, per this project's own established
ponytail/YAGNI discipline).

- [ ] **Step 5: Implement `CopyHash` and its truncation helper**

Build `CopyHash.tsx` per the interface above. Write the failing test for
`truncateMiddle` first:

```ts
import { truncateMiddle } from "./CopyHash"; // or wherever you export it from

describe("truncateMiddle", () => {
  it("truncates a long hash to the given keep length on each side", () => {
    const hash = "a".repeat(32) + "b".repeat(32);
    expect(truncateMiddle(hash, 6)).toBe("aaaaaa…bbbbbb");
  });

  it("returns short strings unchanged", () => {
    expect(truncateMiddle("short", 6)).toBe("short");
  });
});
```

Place this test wherever makes sense given how you structured the export
(a co-located `CopyHash.test.ts`, or folded into `api.test.ts` if you
decided the helper belongs there instead — your call, just make sure it's
covered). Run `cd frontend && npm test` to confirm it fails, implement,
confirm it passes.

- [ ] **Step 6: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/Badge.* frontend/src/components/Card.* frontend/src/components/Toast.* frontend/src/components/ConfirmDialog.* frontend/src/components/CopyHash.*
git commit -m "feat: add shared Badge, Card, Toast, ConfirmDialog, CopyHash primitives"
```

---

### Task 3: Chain-integrity verification endpoint

**Files:**
- Modify: `verdict-engine/audit_log.py`
- Modify: `verdict-engine/tests/test_audit_log.py`
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`
- Modify: `backend/verdicts.go`
- Modify: `backend/main.go` (register the new route)
- Modify: `backend/verdicts_test.go` (create if it doesn't exist — check
  first; `verdicts.go`'s existing handlers may currently be tested
  elsewhere or not at all — match whatever the existing pattern is)

**Interfaces:**
- Produces: `AuditLog.verify_chain_detail(self) -> dict` returning
  `{"intact": bool, "entries": int, "broken_at": int | None}` — `broken_at`
  is **1-indexed** (the human-readable "entry N", not a 0-indexed offset)
  when `intact` is `False`, `None` when `intact` is `True`.
  `AuditLog.verify_chain(self) -> bool` keeps its EXACT existing signature
  and behavior (delegates to the new method internally) — the two existing
  tests asserting `verify_chain() is True`/`is False` must keep passing
  unmodified.
- New route `GET /verify` on the verdict-engine returns
  `audit_log.verify_chain_detail()` as JSON.
- New route `GET /api/audit/verify` on the Go backend proxies it, behind
  `requireAuth` (any authenticated role — this is read-only information,
  not an admin action).

- [ ] **Step 1: Write the failing pytest tests**

Add to `verdict-engine/tests/test_audit_log.py` (read the existing two
`verify_chain` tests first, to match their fixture-setup style exactly):

```python
def test_verify_chain_detail_reports_intact_with_entry_count(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})
    result = log.verify_chain_detail()
    assert result == {"intact": True, "entries": 2, "broken_at": None}


def test_verify_chain_detail_reports_broken_entry_one_indexed(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})
    # Tamper the first line's stored hash, matching however the existing
    # "reports False when tampered" test corrupts a line — read that test
    # and reuse the same tampering technique for consistency.
    lines = log_path.read_text().splitlines()
    import json
    tampered = json.loads(lines[0])
    tampered["entry_hash"] = "0" * 64
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")

    result = AuditLog(log_path).verify_chain_detail()
    assert result["intact"] is False
    assert result["entries"] == 2
    assert result["broken_at"] == 1
```

Run: `cd verdict-engine && python -m pytest tests/test_audit_log.py -k verify_chain_detail -v`
Expected: FAIL — method doesn't exist yet.

- [ ] **Step 2: Implement `verify_chain_detail` in `verdict-engine/audit_log.py`**

Replace the existing `verify_chain` method with:

```python
    def verify_chain_detail(self) -> dict:
        prev_hash = GENESIS_HASH
        records = self.all()
        for i, record in enumerate(records):
            record = dict(record)
            stored_entry_hash = record.pop("entry_hash", None)
            if record.get("prev_log_hash") != prev_hash:
                return {"intact": False, "entries": len(records), "broken_at": i + 1}
            expected = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()
            ).hexdigest()
            if expected != stored_entry_hash:
                return {"intact": False, "entries": len(records), "broken_at": i + 1}
            prev_hash = stored_entry_hash
        return {"intact": True, "entries": len(records), "broken_at": None}

    def verify_chain(self) -> bool:
        return self.verify_chain_detail()["intact"]
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/test_audit_log.py -v`
Expected: PASS, including the two pre-existing `verify_chain` tests
unmodified.

- [ ] **Step 4: Add the `/verify` route to `verdict-engine/app.py`**

Add, near the other `/verdicts` routes:

```python
@app.get("/verify")
def verify_chain_route():
    return audit_log.verify_chain_detail()
```

Add to `verdict-engine/tests/test_app.py`:

```python
def test_verify_route_returns_chain_status():
    resp = client.get("/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert "intact" in body and "entries" in body and "broken_at" in body
```

Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS.

- [ ] **Step 5: Add the `/api/audit/verify` proxy route to the backend**

Read `backend/verdicts.go`'s existing handlers first (they follow a
consistent proxy pattern: GET the verdict-engine, copy status+body
through). Add a new handler in the same file, following that exact
pattern:

```go
func chainVerifyHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := httpClient.Get(verdictEngineURL + "/verify")
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}
```

In `backend/main.go`'s `newMux`, register it alongside the other
`requireAuth`-only routes:

```go
	mux.Handle("/api/audit/verify", requireAuth(store)(chainVerifyHandler(verdictEngineURL)))
```

- [ ] **Step 6: Test the new backend route**

Read whatever existing test file covers `verdicts.go`'s handlers (check
for a `verdicts_test.go` — if none exists, look at how `hashes_test.go`
tests its proxy handlers and follow that exact pattern for consistency).
Add a test that a fake verdict-engine's `/verify` response is proxied
through with status and body intact, matching the style of the existing
`TestHashesHandlerProxiesGet`-shaped tests.

Run: `cd backend && go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add verdict-engine/audit_log.py verdict-engine/tests/test_audit_log.py verdict-engine/app.py verdict-engine/tests/test_app.py backend/verdicts.go backend/main.go
git add -u backend/*_test.go
git commit -m "feat: add a chain-integrity verification endpoint"
```

---

### Task 4: Header and StatStrip

**Files:**
- Create: `frontend/src/components/Header.tsx` + `Header.css`
- Create: `frontend/src/components/StatStrip.tsx` + `StatStrip.css`

**Interfaces:**
- `<Header user={{ username, role }} connState={ConnectionState} monitorIsolated={boolean} onLogout={() => void} />`
  — replaces the `<header>` block currently inline in `App.tsx`. Contains:
  the wordmark (Task 5 builds the actual SVG mark — for this task, use a
  simple placeholder inline SVG or the bare wordmark text; Task 5 will
  supply the final mark and this task's `Header` just needs a slot for it
  — coordinate by exporting a small `<Wordmark />` component from
  `Header.tsx` that Task 5 can either use as-is or you can leave as a
  TODO-free simple shape now, since Task 5 runs after this one and may
  refine it), the live/offline connection indicator (reusing the existing
  `connState` values from `api.ts`, styled with `Badge`-like tone but
  doesn't need to literally use `Badge` if that doesn't fit the header's
  layout), a monitor-connected indicator (derived from `monitorIsolated`),
  the theme toggle button (uses `theme.ts`'s `getStoredTheme`/
  `setStoredTheme`, toggling `document.documentElement.dataset.theme`),
  and the user/role/sign-out control from the brief's wireframe
  (`user ▾ role · Sign out` — a simple button is fine, a dropdown menu is
  not required unless you judge it clearly better; document your choice).
- `<StatStrip verdicts={Verdict[]} hashes={HashEntry[]} />` — computes
  "Samples analyzed" (count of verdict records with a `sample_hash`),
  "Compromised" (count where `verdict === "Compromised"`), "Pending
  approvals" (count of `hashes` where `status === "pending"`), and "Chain
  status" (a small `Badge`-style indicator — this task does NOT call the
  new `/api/audit/verify` endpoint itself; it takes a `chainIntact:
  boolean | null` prop instead, since `App.tsx`/`AuditLogTable`'s area is
  the natural owner of that fetch — wire the actual prop value in Task 9
  or Task 11, whichever ends up owning the verify fetch; for THIS task,
  accept the prop and render its three states (`null` = loading/unknown,
  `true` = intact, `false` = broken) with tabular-number counts for the
  other three stats). No new data-fetching in this component — it's pure
  presentation over data passed in, per the brief's explicit "no new
  endpoints" constraint for the stat strip specifically.

- [ ] **Step 1: Implement `Header`**

Build per the interface above.

- [ ] **Step 2: Implement `StatStrip`**

Build per the interface above.

- [ ] **Step 3: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm run build`
(These two components aren't wired into `App.tsx` yet — that's Task 11 —
so a clean build with them simply unused-but-exported is the bar for this
task; if the build tool flags unused exports as an error rather than a
warning, add a minimal throwaway usage or confirm the config tolerates
it — don't disable the check globally.)

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/Header.* frontend/src/components/StatStrip.*
git commit -m "feat: add Header and StatStrip components"
```

---

### Task 5: Login page redesign

**Files:**
- Modify: `frontend/src/components/LoginPage.tsx`
- Create: `frontend/src/components/LoginPage.css`
- Create: `frontend/public/favicon.svg` (or modify if one already exists —
  check first)
- Modify: `frontend/index.html` (favicon reference, if it needs updating)

**Requirements (design brief, not literal code — exercise craft within
these constraints, matching the Design Plan's principles above):**

- Full-viewport split layout on desktop (≥960px): left ~55% a dark panel
  (`--surface` or `--bg`) containing the wordmark (design a simple SVG
  mark: two overlapping, offset rounded shapes suggesting a duplicated
  "shadow" silhouette — solid `--text` shape in front, `--accent` at
  reduced opacity behind/offset — per the Design Plan above), the tagline
  "Detonate in the shadow. Protect the real.", and three short feature
  bullets with `lucide-react` icons: Isolated detonation · Explainable
  verdicts · Tamper-evident audit. Include the described animated
  background: a single 1px horizontal or vertical line in `--accent`,
  drifting slowly top-to-bottom (or left-to-right) over roughly 8 seconds,
  looping, peak opacity around 15%, implemented in pure CSS (`@keyframes` +
  `animation`), fully paused/hidden under `prefers-reduced-motion: reduce`.
  Right ~45%: a centered `Card`-like form (reuse `Card` from Task 2 if it
  fits, or a bespoke form shell if `Card`'s title-bar shape doesn't suit a
  login form — your call) with username, password (show/hide toggle using
  a `lucide-react` eye icon, `aria-label` on the toggle button), the
  existing "Sign in" button/spinner/caps-lock-warning/error behavior
  (already implemented — keep the logic, restyle the markup), all through
  the new tokens.
- Mobile (<960px): single column, the card only, with the wordmark above
  it (drop the animated panel and feature bullets entirely below the
  breakpoint — don't just visually hide them, since that ships unused
  animation to phones for nothing).
- Keep every existing behavior exactly: `onLogin` prop contract, focus on
  username on load, Enter submits, disabled-while-submitting, the generic
  error message rendering, the caps-lock warning. Don't change `App.tsx`'s
  usage of `<LoginPage onLogin={...} />` — same prop, same behavior,
  restyled implementation.
- Use the wordmark SVG as the favicon too (`frontend/public/favicon.svg`
  and `frontend/index.html`'s `<link rel="icon">` — check what's currently
  there first; Part 1's redesign already added a `favicon.svg`, so this
  task most likely REPLACES its content with the new mark rather than
  adding a new file — verify before assuming either way).
- Accessibility: proper `<label>`s (already present, keep), `autoComplete`
  values (already present, keep), visible focus rings (from Task 1's
  global `:focus-visible` rule — verify it actually shows on this page's
  dark panel, don't let a lower-contrast custom style override it), the
  password show/hide toggle is a real `<button type="button">` with an
  `aria-label` that changes between "Show password"/"Hide password", not
  just an icon swap.

- [ ] **Step 1: Check the current favicon situation**

Read `frontend/index.html` and check whether `frontend/public/favicon.svg`
already exists (Part 1's redesign added one). Decide whether to replace
its contents with the new wordmark mark or how the two relate — document
the decision in your report.

- [ ] **Step 2: Design and build the wordmark SVG**

Build it as a reusable inline `<Wordmark />` (or similar) so `Header.tsx`
(Task 4, already built with a placeholder slot) can use the same mark —
coordinate by exporting it from a small shared location (e.g.
`frontend/src/components/Wordmark.tsx`) rather than duplicating the SVG
markup in both `LoginPage.tsx` and `Header.tsx`. If Task 4 already
shipped its own placeholder, replace it with this shared component in this
task and update `Header.tsx`'s import accordingly — that's an expected,
in-scope adjustment to Task 4's placeholder, not scope creep.

- [ ] **Step 3: Rebuild `LoginPage.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 4: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 5: Manual visual check**

If a headless browser is available in this environment (check for
`playwright` in `node_modules` or install it: `npx playwright install
chromium` — this is a dev-tooling install for verification, not a
project dependency, so it doesn't violate the "no new dependencies"
constraint), take screenshots of the login page at 1440px, 1024px, and
375px widths, in both `data-theme="dark"` and `data-theme="light"`, and
visually confirm: no horizontal scroll, the animated line is present on
desktop and absent on mobile, text contrast looks correct in both themes,
and the layout matches the split description above. Describe what you see
in your report. If no headless browser is available in this environment,
say so explicitly in your report and rely on the type-check/build passing
plus a careful reading of the CSS — don't skip this step silently.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/LoginPage.tsx frontend/src/components/LoginPage.css frontend/src/components/Wordmark.tsx frontend/public/favicon.svg frontend/index.html frontend/src/components/Header.tsx
git commit -m "feat: redesign the login page with wordmark and animated panel"
```

---

### Task 6: Upload panel redesign — drag-and-drop, client-side hash, step stepper

**Files:**
- Modify: `frontend/src/components/UploadPanel.tsx`
- Create: `frontend/src/components/UploadPanel.css`
- Modify: `frontend/src/api.ts` (add `sha256Hex` and `isValidSha256`)
- Modify: `frontend/src/api.test.ts`

**Interfaces:**
- `frontend/src/api.ts` gains:
  ```ts
  export async function sha256Hex(file: File): Promise<string> {
    const buf = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  export function isValidSha256(value: string): boolean {
    return /^[a-f0-9]{64}$/.test(value);
  }
  ```
- `UploadPanel`'s existing props (`onVerdict`, `onUploadStart`,
  `onSessionExpired`) are unchanged.

**Requirements (design brief for the visual/interaction rebuild):**

- Native drag-and-drop (`onDragOver`/`onDrop` handlers, `preventDefault`
  on both so the browser doesn't navigate away) in addition to the
  existing click-to-browse file input — both paths should feel like the
  same drop zone.
- As soon as a file is selected (by either path), compute its SHA-256 with
  `sha256Hex` and show the filename, size (human-readable, e.g. "142 KB"),
  and the hash (via `CopyHash` from Task 2) *before* the user clicks "Run
  sample" — this lets an analyst confirm what they're about to detonate.
- While a run is in progress, show the step list from the brief animating
  through: Upload → Isolate → Detonate → Observe → Score → Teardown. The
  brief says this should be "driven by incoming WebSocket events for that
  run" — this component doesn't currently receive live events as a prop.
  Judgment call: either (a) accept a new prop from `App.tsx` (e.g.
  `latestEventType: string | null`) so `App.tsx` can pass through the
  live feed's most recent event type while a run is active, letting the
  stepper advance in step with real events, or (b) animate the steps on a
  fixed timer as a simpler approximation once the upload request is sent,
  since the backend's `/api/samples` response only arrives once at the
  very end (Upload→Score all complete) and no WebSocket event today marks
  the container start/teardown boundaries specifically. Pick whichever you
  judge gives an honest, non-misleading impression of progress; document
  which you chose and why in your report. Either way, don't fabricate a
  false sense of granular real-time tracking if the underlying data isn't
  actually that granular.
- Error messages stay human and specific (existing behavior — keep the
  401→`onSessionExpired` branch exactly as-is, just restyle around it).

- [ ] **Step 1: Write the failing tests for the two new pure functions**

Add to `frontend/src/api.test.ts`:

```ts
describe("isValidSha256", () => {
  it("accepts a valid 64-character lowercase hex hash", () => {
    expect(isValidSha256("a".repeat(64))).toBe(true);
  });

  it("rejects the wrong length", () => {
    expect(isValidSha256("a".repeat(63))).toBe(false);
  });

  it("rejects uppercase characters", () => {
    expect(isValidSha256("A".repeat(64))).toBe(false);
  });

  it("rejects non-hex characters", () => {
    expect(isValidSha256("g".repeat(64))).toBe(false);
  });
});

describe("sha256Hex", () => {
  it("hashes a known file to its known SHA-256", async () => {
    const file = new File(["hello"], "hello.txt");
    const hash = await sha256Hex(file);
    expect(hash).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});
```

(That expected hash is the real, verifiable SHA-256 of the ASCII string
`hello` — confirm it independently if you have a way to, rather than
trusting this plan blindly, since a wrong expected value here would make a
correct implementation fail.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — neither function exists yet.

- [ ] **Step 3: Implement `sha256Hex`/`isValidSha256` in `api.ts`**

Add the code shown in Interfaces above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS. If the known-hash test fails, double check the test file's
literal string — `crypto.subtle` is available in Vitest's default
`jsdom`-less Node environment via Node's Web Crypto API, so this should
work without special config; if it doesn't, investigate rather than
deleting the test.

- [ ] **Step 5: Rebuild `UploadPanel.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 6: Type-check, run the full frontend suite, and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts frontend/src/components/UploadPanel.tsx frontend/src/components/UploadPanel.css
git commit -m "feat: redesign upload panel with drag-and-drop, client-side hash, step stepper"
```

---

### Task 7: Verdict panel redesign — badge, confidence, causal timeline

**Files:**
- Modify: `frontend/src/components/VerdictPanel.tsx`
- Create: `frontend/src/components/VerdictPanel.css`

**Requirements:**

- Verdict shown via `Badge` (Task 2) — icon + text, never color alone.
- Confidence shown as both a number (`(confidence * 100).toFixed(0)}%`,
  already implemented — keep) and a bar or ring (your call which reads
  better in this layout; a horizontal bar is simpler and fits the
  dense-console aesthetic well, a ring is more distinctive — pick one and
  say why in your report).
- Causal chain rendered as a vertical timeline (a connected line with a
  dot per step, not a bare bulleted list) using the existing
  `causal_chain: string[]` data — **do not** attempt to show a numeric
  "rule weight per step," since the backend's `/score` response only ever
  sends the ordered list of reason strings, never per-step numeric
  weights (verify this yourself by checking `verdict-engine/rule_scorer.py`'s
  `score_events` return shape before writing this component, don't take
  this plan's word for it) — adding that would mean reopening Parts 1/2's
  already-reviewed scoring contract, which is out of scope for a frontend
  redesign plan. This is a deliberate, disclosed scope trim from the
  design brief's literal wording ("timeline with rule weight per step") —
  note it in your report as a known gap, not a silent omission.
  Empty chain → the exact copy "No suspicious behavior observed." (from
  the brief, not a paraphrase).
- Show the sample hash via `CopyHash` (Task 2), the filename, timestamp,
  and the source (`"sample"` vs `"monitor"` — note `Verdict` doesn't
  currently carry a `source` field; check `frontend/src/types.ts`'s
  `Verdict` interface and `App.tsx`'s live-message handling before
  assuming this data is available — if it genuinely isn't threaded through
  today, either thread it through as a small, disclosed additive change
  matching Part 1's `source` tagging pattern already established on
  `LiveMessage`, or omit that one field and note the gap in your report;
  your call based on how much surface that touches).
- Empty state (no verdict yet): an elegant, illustration-free placeholder
  — brief copy explaining what will appear here once a sample runs, not
  the current bare "No verdict yet. Upload a sample to see what it does."
  (keep the spirit, tighten the wording if you judge it reads better,
  matching this project's plain, direct interface-voice convention).

- [ ] **Step 1: Verify the causal-chain data shape**

Read `verdict-engine/rule_scorer.py`'s `score_events` function to confirm
it returns `(confidence: float, chain: List[str])` with no per-item
weight — this confirms the scope trim above is accurate, not assumed.

- [ ] **Step 2: Check whether `source` is available on `Verdict`**

Read `frontend/src/types.ts` and `frontend/src/App.tsx`'s
`shouldUpdateSampleVerdict`/live-message handling to determine whether the
verdict object ever carries which path (`sample` vs `monitor`) produced
it, distinct from the `LiveMessage` envelope's own `source` field (which
is not stored anywhere once `setVerdict(msg.data)` runs). Decide per the
requirements above.

- [ ] **Step 3: Rebuild `VerdictPanel.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 4: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/VerdictPanel.tsx frontend/src/components/VerdictPanel.css
git commit -m "feat: redesign verdict panel with badge, confidence bar, causal timeline"
```

---

### Task 8: Event feed redesign — tabs, filter chips, monitor events

**Files:**
- Modify: `frontend/src/components/EventFeed.tsx`
- Create: `frontend/src/components/EventFeed.css`
- Modify: `frontend/src/api.ts` (a second reducer for monitor-source events)
- Modify: `frontend/src/api.test.ts`
- Modify: `frontend/src/App.tsx` (track monitor events alongside sample events)

**Interfaces:**
- `frontend/src/api.ts` gains a sibling to `applyLiveEvent`:
  ```ts
  export function applyMonitorEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[] {
    if (msg.type !== "event" || msg.source !== "monitor") return events;
    return [...events, msg.data].slice(-MAX_EVENTS);
  }
  ```
  (Reuses the same `MAX_EVENTS` constant `applyLiveEvent` already defines
  in that file — don't duplicate the literal `500`.)
- `EventFeed` gains props: `sampleEvents: MirraEvent[]`, `monitorEvents: MirraEvent[]` (replacing the current single `events` prop — update the one
  call site in `App.tsx` accordingly), and renders two tabs ("Shadow run" /
  "Endpoint monitor") switching which list is shown, using correct
  `tablist`/`tab`/`tabpanel` ARIA roles and arrow-key navigation between
  tabs.

**Requirements:**

- Filter chips (Process · File · Network) above the active tab's list,
  client-side filtering by `event_type` — multiple chips can presumably be
  toggled independently (all-on by default); your call on exact
  interaction, just keep it simple and keyboard-operable.
- Each row: a `lucide-react` icon per event type, a color-coded left
  border/rule (use `--accent` or a neutral tone — NOT a `--sev-*` color,
  since raw events aren't verdicts and Principle 3 in the Design Plan
  reserves severity color for verdict-bearing surfaces only), monospace
  detail (existing `detail()` helper — keep the logic, restyle), a
  relative timestamp with the full ISO string available on hover (e.g. via
  `title=`) — the current `formatTime` shows only a local clock time, not
  "relative" (e.g. "2s ago") — decide whether to keep clock-time (arguably
  more useful for a live trace where every row is recent, so relative time
  would mostly read as "just now" repeatedly) or switch to relative time
  as the brief literally says; your call, document which you picked and
  why.
- Rows that match a scoring rule (sensitive-path write, non-standard port,
  child-process spawn) get a small tag naming the rule — this requires
  client-side re-detection of the same conditions `rule_scorer.py` checks
  (sensitive path prefixes, non-standard ports, any process spawn), since
  raw `MirraEvent`s don't carry a "this triggered rule X" flag from the
  backend. Read `verdict-engine/rule_scorer.py`'s constants
  (`SENSITIVE_PREFIXES`, `STANDARD_PORTS`) and mirror the same conditions
  in a small TypeScript helper — keep the two lists loosely in sync in
  spirit (exact values, not imported/shared, since there's no existing
  mechanism to share constants across the Go/Python/TypeScript boundary in
  this project, and inventing one is out of scope for this task).
- Auto-scroll to newest unless the user has scrolled up, in which case
  show a "↓ N new events" pill instead of yanking their scroll position —
  implement via a scroll-position check (near-bottom threshold) on the
  list container.
- Empty state per tab: brief, elegant, tab-specific copy ("No trace yet —
  upload a sample to begin." already exists for the shadow-run case; write
  an analogous one for the monitor tab).

- [ ] **Step 1: Write the failing test for `applyMonitorEvent`**

Add to `frontend/src/api.test.ts`, mirroring the existing `applyLiveEvent`
test block's structure exactly (same `makeEvent` helper if it's still
in-file, reuse it):

```ts
describe("applyMonitorEvent", () => {
  it("appends a monitor-source event", () => {
    const result = applyMonitorEvent([], { type: "event", source: "monitor", data: makeEvent("e1") });
    expect(result).toHaveLength(1);
  });

  it("ignores a sample-source event", () => {
    const result = applyMonitorEvent([], { type: "event", source: "sample", data: makeEvent("e1") });
    expect(result).toHaveLength(0);
  });

  it("ignores non-event messages", () => {
    const result = applyMonitorEvent([makeEvent("e1")], { type: "isolated" });
    expect(result).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test`
Expected: FAIL — `applyMonitorEvent` doesn't exist yet.

- [ ] **Step 3: Implement `applyMonitorEvent` in `api.ts`**

Add the code from Interfaces above, placed next to `applyLiveEvent`.

- [ ] **Step 4: Wire monitor events into `App.tsx`**

Add a `monitorEvents` state array alongside the existing `events` state
(consider renaming `events` to `sampleEvents` for clarity now that there
are two — a mechanical rename, low risk, do it if it clearly improves
readability at the call sites you're touching anyway). Update the
WebSocket message handler to also call `applyMonitorEvent`, and pass both
arrays into `<EventFeed sampleEvents={...} monitorEvents={...} />`.

- [ ] **Step 5: Rebuild `EventFeed.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 6: Type-check, run the full frontend suite, and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts frontend/src/components/EventFeed.tsx frontend/src/components/EventFeed.css frontend/src/App.tsx
git commit -m "feat: redesign event feed with shadow-run/monitor tabs and filter chips"
```

---

### Task 9: Audit log redesign — pagination, search, actor column, chain indicator

**Files:**
- Modify: `frontend/src/components/AuditLogTable.tsx`
- Create: `frontend/src/components/AuditLogTable.css`
- Modify: `frontend/src/api.ts` (add `fetchChainStatus`)
- Modify: `frontend/src/api.test.ts`

**Interfaces:**
- `frontend/src/api.ts` gains:
  ```ts
  export type ChainStatus = { intact: boolean; entries: number; broken_at: number | null };

  export async function fetchChainStatus(): Promise<ChainStatus> {
    return request("/api/audit/verify");
  }
  ```

**Requirements:**

- Sticky table header, hairline row dividers (no zebra striping — matches
  the Design Plan's "one elevation step" principle, zebra striping is a
  second implied surface).
- Verdict shown via `Badge` (icon + text, not just a colored dot as today).
- An actor column (the `actor` field already exists on verdict AND action
  records since Part 2 — check `AuditRow`'s current shape in this file and
  extend it, don't invent a new field name).
- Copy-able hashes via `CopyHash` (Task 2).
- Client-side pagination, 25 rows per page.
- A search box filtering the currently-loaded rows by hash, verdict, or
  actor (client-side substring match against already-fetched data — no
  new backend search endpoint).
- The chain-integrity indicator: fetch `fetchChainStatus()` (on mount and
  whenever `refreshKey` changes, same pattern the existing `fetchVerdicts`
  effect already uses) and render "✓ Chain intact · N entries" or a rose
  "✗ Chain broken at entry N" prominently — the brief calls this "the
  log's headline feature, make it visible," so it should not be a small
  corner label; put it at the top of the card, above the search/pagination
  controls.
- Relative time with the full ISO string on hover (same judgment call as
  Task 8 — decide independently for this component, since a historical
  log table has a much stronger case for relative time than a live trace
  does; you don't need to make the same choice in both places if the
  contexts genuinely differ, just be consistent about *why*).

- [ ] **Step 1: Write the failing test for `fetchChainStatus`**

Add to `frontend/src/api.test.ts`, matching the existing `fetchVerdicts`
test's structure:

```ts
it("fetchChainStatus calls the backend audit/verify endpoint", async () => {
  (fetch as any).mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ intact: true, entries: 3, broken_at: null }),
  });
  const result = await fetchChainStatus();
  expect(fetch).toHaveBeenCalledWith("/api/audit/verify", expect.objectContaining({ credentials: "same-origin" }));
  expect(result).toEqual({ intact: true, entries: 3, broken_at: null });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test`
Expected: FAIL — `fetchChainStatus` doesn't exist yet.

- [ ] **Step 3: Implement `fetchChainStatus` in `api.ts`**

Add the code from Interfaces above.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test`
Expected: PASS.

- [ ] **Step 5: Rebuild `AuditLogTable.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 6: Type-check, run the full frontend suite, and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts frontend/src/components/AuditLogTable.tsx frontend/src/components/AuditLogTable.css
git commit -m "feat: redesign audit log with pagination, search, actor column, chain indicator"
```

---

### Task 10: Hash approvals redesign — confirm dialogs, count badge, validation

**Files:**
- Modify: `frontend/src/components/PendingHashApprovals.tsx`
- Create: `frontend/src/components/PendingHashApprovals.css`

**Interfaces:**
- `PendingHashApprovals` gains a `role: "admin" | "analyst"` prop (from
  `App.tsx`'s already-known `user.role`) so it can render Approve/Reject
  as disabled/hidden for analysts (read-only per the spec's role model —
  Part 2's backend already 403s an analyst's approve/reject call, so this
  is a UX improvement hiding an action that would fail anyway, not a new
  security boundary).

**Requirements:**

- A count badge showing the number of pending entries — this component
  currently renders standalone; if `App.tsx`'s Task 11 assembly puts this
  behind a tab (per the brief's "Tabs: Audit log | Hash approvals (count
  badge)"), the badge itself can be rendered by whatever owns the tab
  strip (Task 11) using a `pendingCount` value this component exposes
  (e.g. via a callback prop `onPendingCountChange?: (n: number) => void`
  called whenever `pending.length` changes) — coordinate with Task 11's
  requirements below rather than duplicating the tab UI inside this
  component itself.
- Approve and Reject both open a `ConfirmDialog` (Task 2) showing the full
  untruncated hash and label before committing — no more instant action on
  click.
- Manual hash submission form: validate with `isValidSha256` (Task 6)
  before allowing submit, with an inline field error (not just a failed
  network request) when the pattern doesn't match. Analysts see the
  pending list read-only per the `role` prop but the submit form stays
  available to them (per the spec: analysts can propose hashes, only
  admins approve/reject — matches how the backend already scopes it).

- [ ] **Step 1: Rebuild `PendingHashApprovals.tsx` and its CSS**

Implement per the requirements above.

- [ ] **Step 2: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/PendingHashApprovals.tsx frontend/src/components/PendingHashApprovals.css
git commit -m "feat: redesign hash approvals with confirm dialogs and validation"
```

---

### Task 11: Dashboard assembly — App.tsx, isolation banner, tabs, loading states, generalized error handling

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/MonitorBanner.tsx`
- Create: `frontend/src/components/MonitorBanner.css`
- Create: `frontend/src/components/Tabs.tsx` + `Tabs.css` (a small shared
  tab-strip component, since Task 8's event-feed tabs and this task's
  audit-log/hash-approvals tabs are two separate instances of the same
  pattern — this is exactly the "reused 2+ times" case the brief's Code
  Structure section calls out for a shared piece)
- Create: skeleton-loading CSS (fold into whichever files render the
  loading state, or a small shared `Skeleton.tsx` if that's cleaner — your
  call)

**Requirements:**

- Assemble the full dashboard layout matching the brief's ASCII wireframe:
  `Header` → isolation banner (only when isolated) → two-column zone
  (Detonate + Verdict cards left, Live telemetry/EventFeed right) →
  tabbed Audit log / Hash approvals section at the bottom. `StatStrip`
  under the header (the brief marks this optional-but-recommended — build
  it, since Task 4 already exists and it's a small addition). Read the
  CURRENT `App.tsx` first — Task 8 (already complete before this task
  runs) already added `sampleEvents`/`monitorEvents` state and wired both
  into `EventFeed`'s two-prop interface; this task assembles the
  surrounding layout around that existing wiring, it does not replace or
  re-derive it. If anything about Task 8's actual final shape doesn't
  match what's described elsewhere in this task's brief, defer to what
  you actually find in the file.
- Build `Tabs.tsx` as the shared primitive Task 8 (Shadow run / Endpoint
  monitor) and this task (Audit log / Hash approvals) both use — correct
  ARIA roles (`tablist`/`tab`/`tabpanel`), arrow-key navigation, and (per
  the Code Structure note above) go back and refactor Task 8's `EventFeed`
  tab markup to use this shared component if Task 8 built its own
  inline version first — whichever task runs second reconciles with the
  first; document in your report which direction this went.
- The Hash Approvals tab's label shows a count badge (wired from Task 10's
  `onPendingCountChange` callback or equivalent).
- Wire `StatStrip`'s `chainIntact` prop from a `fetchChainStatus()` call
  owned at the `App.tsx` level (or leave it owned inside `AuditLogTable`
  from Task 9 and pass the result up via a callback — your call which is
  architecturally cleaner given how `refreshKey` already flows through
  this component tree, just don't fetch chain status from two places).
- Isolation banner restyle: rose surface (`--sev-compromised`-family
  tokens), a `lucide-react` shield-alert icon, a pulsing dot (respecting
  `prefers-reduced-motion`), the isolation timestamp (check whether this
  data is currently available — `MonitorBanner`'s props today are just
  `isolated`/`onReconnected`; if no timestamp is threaded through from the
  backend, note the gap rather than fabricating one), and a Reconnect
  button visible/enabled only for `role === "admin"` (again, the backend
  already 403s an analyst's attempt — this is a UX improvement, not a new
  boundary), gated behind a `ConfirmDialog`.
- `aria-live="polite"` region announcing verdict/feed updates — pick a
  concrete, unobtrusive implementation (e.g. a visually-hidden live region
  updated with a short text summary whenever a new verdict or a new
  isolation event arrives) rather than making the entire feed list itself
  a live region (which would spam a screen reader on every single trace
  row).
- Skeleton loading states: on first mount, before `AuditLogTable`,
  `PendingHashApprovals`, and `StatStrip`'s data has arrived, show a
  shimmer placeholder shaped like the eventual content rather than a bare
  spinner or blank space — apply consistently across all three.
- Generalize 401/403 handling per the brief ("`request()` ... throws a
  typed error with status (so 401 → logout, 403 → 'Admins only' toast)"):
  Part 2 only wired 401-handling into `UploadPanel`. Extend the same
  pattern to `AuditLogTable`/`PendingHashApprovals`'s existing `catch`
  blocks — on `ApiError` with `status === 401`, trigger the same
  session-expiry flow `UploadPanel` already uses (you'll need to thread an
  `onSessionExpired` callback into these two components as well, matching
  the existing pattern rather than inventing a new one); on `status ===
  403`, push a Toast ("Admins only") via `useToast()` instead of the
  generic inline error text.
- Responsive: verify (don't just assume) no horizontal scroll at 375px —
  the two-column zone collapses to one column below 960px per the brief,
  16px gutters on phones.

- [ ] **Step 1: Build `Tabs.tsx`**

Implement the shared tab-strip primitive per the requirements above.

- [ ] **Step 2: Reconcile with Task 8's event-feed tabs**

Check how Task 8 implemented its tabs; refactor to share `Tabs.tsx` if
Task 8 built something bespoke.

- [ ] **Step 3: Rebuild `MonitorBanner.tsx` and its CSS**

Implement per the isolation-banner requirements above.

- [ ] **Step 4: Build skeleton loading states**

Implement per the requirements above.

- [ ] **Step 5: Assemble the final `App.tsx`**

Wire `Header`, `StatStrip`, the isolation banner, the two-column
detonation zone, and the tabbed audit-log/hash-approvals section. Wire the
generalized 401/403 handling into `AuditLogTable`/`PendingHashApprovals`.
Add the `aria-live` region.

- [ ] **Step 6: Type-check, run the full frontend suite, and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`

- [ ] **Step 7: Manual responsive/visual check**

Same as Task 5's Step 5 — screenshots at 1440px, 1024px, 375px, both
themes, if a headless browser is available; describe findings in your
report either way. Specifically confirm: no horizontal scroll at 375px,
the isolation banner (trigger it if you can, e.g. by temporarily rendering
with `isolated=true` in a throwaway local check, then revert) reads
clearly, tabs are keyboard-operable (Tab to focus, arrow keys to switch,
Enter/Space to activate).

- [ ] **Step 8: Commit**

```bash
git add frontend/src/App.tsx frontend/src/components/Tabs.* frontend/src/components/MonitorBanner.* frontend/src/components/EventFeed.tsx frontend/src/components/AuditLogTable.tsx frontend/src/components/PendingHashApprovals.tsx
git commit -m "feat: assemble the redesigned dashboard layout"
```

---

### Task 12: Accessibility pass, documentation, cleanup

**Files:**
- Modify: `frontend/src/index.css` (remove any now-dead Part 1-era rules
  Task 1 flagged as stale)
- Modify: `docs/concepts.md`
- Modify: `README.md`
- Any component file, as needed, to close accessibility gaps found in this
  pass

**Requirements:**

- Read back through Task 1's report for the list of stale Part 1-era CSS
  rules/variable names flagged as pending — by this point every component
  that owned them has been rewritten, so remove the dead rules now.
- Full accessibility sweep across the whole app: every icon-only button
  has an `aria-label`; every dialog closes on Esc and returns focus; every
  tab strip is keyboard-operable; run a contrast check (manually compute
  or reason through contrast ratios, or use a tool if this environment has
  one available) for `--text`/`--text-muted`/`--text-faint` against both
  `--bg` values (dark and light) and against `--surface`/`--surface-2` —
  fix any combination actually used for body text that falls under 4.5:1.
- Update `docs/concepts.md` with a short "Frontend redesign (Part 3)"
  note summarizing the design system (tokens, the two font packages, the
  chain-integrity endpoint) if Task 1 didn't already cover this in enough
  detail — check what's there first, don't duplicate.
- Update `README.md` if the redesign changes anything a new contributor
  would need to know to run the app (it shouldn't — no new env vars, no
  new setup steps — confirm this rather than assuming, and add a note only
  if something genuinely changed).

- [ ] **Step 1: Remove dead CSS**

- [ ] **Step 2: Accessibility sweep**

Go through every component this plan touched and verify the specific
requirements listed above. Fix what's missing.

- [ ] **Step 3: Documentation**

- [ ] **Step 4: Full suite**

Run: `cd backend && go build ./... && go vet ./... && go test ./...`
Run: `cd verdict-engine && python -m pytest tests/ -q`
Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm run lint && npm test && npm run build`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: accessibility pass, remove dead CSS, update docs"
```

---

## Definition of done for this plan

- `cd backend && go build ./... && go vet ./... && go test ./...` passes.
- `cd verdict-engine && python -m pytest tests/ -q` passes.
- `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm run lint && npm test && npm run build` passes.
- Manually verified (screenshots where a headless browser is available,
  otherwise careful reasoning documented in task reports) at 1440px,
  1024px, and 375px widths, in both themes: no horizontal scroll, no
  overlapping text, the login page's split layout and mobile single-column
  both render correctly, the dashboard's two-column zone collapses
  correctly below 960px.
- Accessibility requirements from Global Constraints hold across every
  redesigned component (Task 12 is the checkpoint, but every task's own
  review should already be checking its own surface as it goes).
- `docs/concepts.md` and `README.md` updated per Task 12.
- Twelve commits land in this plan's order, each building and passing
  tests on its own.
