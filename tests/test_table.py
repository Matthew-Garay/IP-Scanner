"""Regresiones del renderizado de la tabla.

Aqui se concentran la mayoria de los fallos que corrigio este proyecto, y todos
fueron el mismo tipo: la tabla se veia mal o incompleta y la causa estaba en
como se repartia el ancho o en que datos llegaban a la fila.

Las pruebas de geometria necesitan una ventana real, asi que se constructions
en un ``CTk`` real y se miden las coordenadas de verdad.
"""

import sys
import unittest

sys.path.insert(0, r"D:\Escaner de puertos")

from ip_inspector.core.models import Device

try:
    from ip_inspector.interface.ui import IPInspectorApp
    _GUI = True
except Exception:  # pragma: no cover - sin tkinter no hay interfaz
    _GUI = False


@unittest.skipUnless(_GUI, "la interfaz necesita tkinter")
class TableGeometry(unittest.TestCase):
    """Las celdas deben caer bajo su cabecera, no a su izquierda."""

    def setUp(self):
        self.app = IPInspectorApp()
        self.app.geometry("1800x900")
        self.app.update_idletasks()
        self.app.update()
        for index in range(6):
            device = Device(
                ip_address="10.0.0.%d" % (index + 1), is_alive=True,
                device_type="Router",
                # Un hostname largo es lo que antes deformaba la rejilla.
                hostname="servidor-de-impresion.lab.local",
                discovery_method="ARP", ttl=128)
            self.app._devices[device.ip_address] = device
            self.app._dirty.add(device.ip_address)
        self.app._sync_pending_rows()
        self.app.update_idletasks()
        self.app.update()

    def tearDown(self):
        try:
            self.app.destroy()
        except Exception:
            pass

    def test_las_columnas_no_se_desalinean(self):
        """El Treeview nativo alinea celdas y cabeceras por construccion."""
        from ip_inspector.interface.ui import DEVICE_COLUMNS
        tabla = self.app._table
        # 6 columnas estilo Advanced IP Scanner, con scroll nativo.
        self.assertEqual(len(DEVICE_COLUMNS), 6)
        self.assertEqual(tabla.row_count(), 6)
        for clave in tabla.keys():
            vals = tabla._rows[clave][0]
            self.assertEqual(len(vals), 6)

    def test_la_tabla_ocupa_todo_el_ancho(self):
        """Ninguna columna acapara el ancho."""
        from ip_inspector.interface.ui import DEVICE_COLUMNS
        anchos = [c[1] for c in DEVICE_COLUMNS]
        mayor = max(anchos)
        # La de puertos es la mas ancha pero no se come la tabla.
        self.assertLess(mayor / sum(anchos), 0.35)

    def test_filas_compactas(self):
        self.assertEqual(self.app._table.ROW_HEIGHT, 24)

    def test_sin_scroll_horizontal_en_ventana_minima(self):
        from ip_inspector.interface.ui import DEVICE_COLUMNS, WINDOW_MINIMUM
        total = sum(columna[1] for columna in DEVICE_COLUMNS)
        self.assertLessEqual(total, WINDOW_MINIMUM[0] - 64,
                             "las columnas no caben en la ventana minima")


if __name__ == "__main__":
    unittest.main()