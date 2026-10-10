#!/usr/bin/env python3
"""Launcher: python gumshoe.py <command> ... (no install needed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gumshoe.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
