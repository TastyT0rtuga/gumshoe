"""Pure-Python third-party packages shipped with Gumshoe so the offline bundle needs no extra install step.
`gumshoe.vendor.use()` puts this directory on sys.path (after the venv's own packages)."""
import sys
from pathlib import Path


def use() -> None:
    p = str(Path(__file__).resolve().parent)
    if p not in sys.path:
        sys.path.append(p)
