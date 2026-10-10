"""Gumshoe — offline, cited forensic triage for Linux server images.

Established tools (UAC, Loki, GoAccess, Chainsaw) do the finding. Gumshoe runs
them, keeps their raw output, normalizes everything into one findings table
with provenance, indexes it, answers questions with a local model under a
citation guard, archives every cited file with its hash, and keeps a
hash-chained custody log of every action.
"""

__version__ = "0.1.0"
