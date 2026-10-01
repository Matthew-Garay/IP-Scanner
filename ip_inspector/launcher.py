"""Launcher for IP Inspector.

This is the file PyInstaller freezes into ``IP_Inspector.exe`` and the file
an operator double-clicks to start the app without a console.

Why it exists: ``main.py`` uses a relative import (``from .interface.ui
import ...``), which PyInstaller's analyser only half-resolves — it bundles
``main.py`` but none of the sibling subpackages. Importing the entry point
absolutely (``from ip_inspector.main import main``) makes the whole package
visible to the analyser, so every layer ends up inside the .exe. The file is
itself importable by the GUI test harness without side effects.

Run it from the folder that contains ``launcher.py``::

    python launcher.py
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ip_inspector.main import main


if __name__ == "__main__":
    sys.exit(main())
