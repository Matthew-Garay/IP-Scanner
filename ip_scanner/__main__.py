"""``python -m ip_scanner``: the window, or the CLI when arguments are given.

    python -m ip_scanner                      # opens the window
    python -m ip_scanner 192.168.1.0/24 -p quick   # command-line scan
"""

import sys

if len(sys.argv) > 1:
    from .cli import main
else:
    from .main import main

sys.exit(main())
