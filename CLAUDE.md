# Mirraura — Project Instructions

## Keep the tech notes current

`docs/concepts.md` is the living reference teammates use to understand what this project is, what languages/tools it uses, and why. Whenever a new language, library, framework, or major tool gets added to the project:

1. Add an entry to `docs/concepts.md` under "Languages — what and why" or "Tools & libraries — what and why" — what it is, why it was chosen over the alternatives, in plain English.
2. If it changes the high-level architecture (a new service, a new major component), update the "About This Project" section's architecture summary too.

Do this as part of the same change that introduces the new dependency — not as a follow-up task to remember later.

## Project conventions

- Spec: `docs/superpowers/specs/2026-09-07-mirraura-design.md`
- Build plan: `docs/superpowers/plans/2026-09-07-mirraura.md`
- No "prototype" or day-count framing in committed docs, filenames, or titles — this is referred to as just "Mirraura," not "the prototype" or "Day N."
- Ponytail discipline: minimum code that works, no unrequested abstractions, reuse before adding a new dependency.
