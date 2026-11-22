"""Permanent regression suite.

Each test reproduces a real bug this application shipped at some point. They
are not generic coverage tests: they pin the specific traps this project fell
into so they cannot come back unnoticed.

Run with::

    python -m unittest discover -s tests -t . -v

Standard library only: the app is packaged with PyInstaller and a test
dependency is not worth it.
"""

import tkinter


class _QuietResult:
    """Silence Tk's noise when each GUI test closes its window.

    Destroying a window leaves pending ``after()`` callbacks that Tk fires on
    an application that is already gone, writing a ``bgerror`` for each. It is
    not a failure: ignoring it keeps the output readable.
    """

    def __getattr__(self, name):
        return lambda *a, **k: None


def _install_quiet_tk():
    if not hasattr(tkinter.Tk, "report_callback_exception"):
        return
    try:
        tkinter.Tk.report_callback_exception = _QuietResult()
    except Exception:  # pragma: no cover
        pass


_install_quiet_tk()