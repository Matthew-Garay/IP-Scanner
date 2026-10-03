"""Regresiones del pintado incremental de la tabla.

Dos fallos que costaron una correccion urgente:

* La cola guardaba el objeto ``Device`` tal como estaba al encolarse. El
  escaner no muta ese objeto: emite uno nuevo ya enriquecido. Una fila que
  esperaba su widget se pintaba con el hostname y los puertos de siempre ("-")
  en vez de los detectados despues.
* Las filas se anadian en orden de descubrimiento, no en el de la columna
  activa, de modo que una rafaga de resultados aparecia desordenada.
"""

import sys
import unittest

sys.path.insert(0, r"D:\Escaner de puertos")

from ip_inspector.core.models import Device

try:
    from ip_inspector.interface.ui import IPInspectorApp, ROW_BUDGET_PER_PAINT
    _GUI = True
except Exception:  # pragma: no cover
    _GUI = False


@unittest.skipUnless(_GUI, "la interfaz necesita tkinter")
class IncrementalPaint(unittest.TestCase):

    def setUp(self):
        self.app = IPInspectorApp()

    def tearDown(self):
        try:
            self.app.destroy()
        except Exception:
            pass

    def test_una_fila_encolada_muestra_el_dato_mas_reciente(self):
        """La fila encolada debe mostrar el equipo, no la foto que la encolo."""
        primero = Device(ip_address="10.0.0.1", is_alive=True,
                         discovery_method="ARP")
        self.app._devices[primero.ip_address] = primero
        self.app._dirty.add(primero.ip_address)
        self.app._sync_pending_rows()
        # Esta fila queda en la cola por el presupuesto de pintado.
        for index in range(ROW_BUDGET_PER_PAINT * 3):
            device = Device(ip_address="10.0.1.%d" % (index + 1), is_alive=True)
            self.app._devices[device.ip_address] = device
            self.app._dirty.add(device.ip_address)
        self.app._sync_pending_rows()

        # El escaner emite un objeto NUEVO ya enriquecido, como hace el hilo.
        enriquecido = Device(
            ip_address=primero.ip_address, is_alive=True,
            discovery_method="ARP", hostname="servidor-nuevo",
            vendor="Cisco Systems")
        self.app._devices[primero.ip_address] = enriquecido
        self.app._dirty.add(primero.ip_address)

        guard = 0
        while (self.app._dirty or self.app._pending_rows) and guard < 500:
            self.app._sync_pending_rows()
            guard += 1

        fila = self.app._row_cache.get(primero.ip_address)
        self.assertIsNotNone(fila, "la fila desaparecio")

        # Las posiciones se buscan por clave de orden y no por numero: la
        # columna de icono inserto una y estas pruebas deben seguir valiendo
        # cuando la rejilla cambie de nuevo.
        from ip_inspector.interface.ui import DEVICE_COLUMNS
        indice = {columna[4]: n for n, columna in enumerate(DEVICE_COLUMNS)}
        self.assertEqual(fila[indice["hostname"]], "servidor-nuevo",
                         "la fila muestra el hostname antiguo")
        self.assertEqual(fila[indice["vendor"]], "Cisco Systems")

    def test_las_filas_respetan_el_orden_de_la_columna_activa(self):
        """Una rafaga de llegadas no debe aterrizar desordenada."""
        self.app._clear_devices()
        self.app._sort_key = "ip"
        self.app._sort_reverse = False
        total = ROW_BUDGET_PER_PAINT * 3
        for index in range(total):
            ip = "10.0.0.%d" % (index + 1)
            device = Device(ip_address=ip, is_alive=True)
            self.app._devices[ip] = device
            self.app._dirty.add(ip)
        guard = 0
        while (self.app._dirty or self.app._pending_rows) and guard < 500:
            self.app._sync_pending_rows()
            guard += 1

        self.app._render_table(force=True)
        claves = self.app._table.keys()
        self.assertEqual(len(claves), total, "se perdio alguna fila")
        esperadas = sorted(
            (d.ip_address for d in self.app._devices.values()),
            key=lambda ip: tuple(int(o) for o in ip.split(".")))
        self.assertEqual(claves, esperadas, "las filas no estan ordenadas")

    def test_el_presupuesto_respeta_el_ritmo_de_llegada(self):
        """Un pintado no crea todas las filas de golpe."""
        for index in range(ROW_BUDGET_PER_PAINT * 3):
            ip = "10.0.0.%d" % (index + 1)
            device = Device(ip_address=ip, is_alive=True)
            self.app._devices[ip] = device
            self.app._dirty.add(ip)
        self.app._sync_pending_rows()
        self.assertLessEqual(self.app._table.row_count(), ROW_BUDGET_PER_PAINT)
        self.assertTrue(self.app._pending_rows,
                        "lo que excede deberia quedar en cola")


if __name__ == "__main__":
    unittest.main()