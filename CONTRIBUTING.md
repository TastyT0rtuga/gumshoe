# Contributing

Thanks for helping. The project has three rules that every change keeps:

1. **The evidence is read-only.** Code opens evidence for reading only and writes only inside the case
   directory. Database or archive work happens on copies.
2. **Everything is logged.** External tools run through `runners.run_cmd`; other state changes
   (archive, export, notes, pins, translations, reports) append to the custody log.
3. **The model never produces a finding.** Findings come from established tools or documented
   deterministic checks and carry provenance (`with_provenance`). The model answers and drafts over
   retrieved, numbered sources; anything it cites outside them is removed.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python gumshoe.py selftest          # must pass before you open a PR
```

The self-test builds a benign synthetic tree with sample outputs of every tool and exercises the whole
pipeline without a model. Add a check there for anything you add.

## Adding a profile or tool

See `docs/PROFILES.md` (profiles, normalizer registry) and `docs/TOOLS.md` (runner conventions).
Sample tool output for tests goes in the self-test generator or `tests/samples/`; it must be
synthetic — no real indicators, hostnames, or case material.

## Detection content

Do not add malware signatures or attack payloads to this repository. Detection belongs to the
upstream rule sets (signature-base, Sigma) that the tools load; Gumshoe's own checks are structural
(accounts, persistence locations, timestamps, configuration).

## Style

Standard library first; optional dependencies degrade gracefully. Keep memory bounded on large
images (stream, use SQLite, cap collections) — see the "Large images" section of the README.
