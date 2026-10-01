"""Application entry point for IP Inspector.

Run it as ``python -m ip_inspector.main`` from the folder above this package,
or as a plain script (``python ip_inspector/main.py``); both work.
"""

from __future__ import annotations

import sys

# Support "python main.py" as well as "python -m ip_inspector.main". This has
# to run before the relative import below, otherwise the import sees no parent
# package and the fallback never gets a chance to establish one.
if __package__ in (None, ""):
    import pathlib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    __package__ = "ip_inspector"

import logging

from .interface.ui import APP_AUTHOR, APP_NAME, launch


def main() -> int:
    """Configure logging and run the graphical interface."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logging.getLogger(__name__).debug("Starting %s by %s", APP_NAME, APP_AUTHOR)

    try:
        launch()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    # The bootstrap above already established the parent package, so this
    # works both as "python -m ip_inspector.main" and "python main.py".
    sys.exit(main())