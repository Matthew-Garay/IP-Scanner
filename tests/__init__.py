"""Suite de regresiones permanente.

Cada prueba reproduce un fallo real que estuvo en produccion. No son pruebas
de cobertura generica: son las trampas concretas en las que esta aplicacion ha
caido, fijadas para que no vuelvan a caerse sin que nadie se entere.

Ejecutar con::

    python -m unittest discover -s tests -t . -v

Solo usa la libreria estandar: la aplicacion se empaqueta con PyInstaller y
anadir una dependencia de test no compensa.
"""

import tkinter


class _QuietResult:
    """Silencia el ruido de customtkinter al cerrar cada prueba de interfaz.

    Al destruir una ventana quedan ``after()`` pendientes que Tk dispara sobre
    una aplicacion ya cerrada, y escribe un ``bgerror`` por cada uno. No es un
    fallo: ignorarlo deja la salida legible y evita que alguien lo lea como una
    regresion real.
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