# Mirraura

A shadow-honeypot prototype: it detonates uploaded files inside a throwaway,
network-isolated Docker container and scores their behavior for verdicts
like `Suspicious` or `Compromised`.

## Prerequisites

- Docker (with Docker Compose)

## Running it

```
cp .env.example .env
./setup.sh
```

Once the stack is up, the dashboard is at http://localhost:5173.

## Demo samples

See `samples/` for files to upload through the dashboard. If you want to try
the EICAR test file specifically, read `samples/EICAR.md` first — Windows
Defender quarantines it on sight, so it needs to be regenerated manually.

## How it works

- `docs/concepts.md` — architecture and concepts overview
- `docs/superpowers/specs/2026-09-07-mirraura-design.md` — full design spec
