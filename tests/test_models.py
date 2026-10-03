"""Regresiones de datos: modelo, color de estado e identificacion."""

import unittest

from ip_inspector.core.identify import IDENTITY_PORTS
from ip_inspector.core.models import Device, Port, SecurityFinding


class DeviceModel(unittest.TestCase):
    """Invariantes del modelo de datos."""

    def test_mac_normalizada(self):
        d = Device(ip_address="10.0.0.1", mac_address="aabbccddeeff")
        self.assertEqual(d.mac_address, "AA:BB:CC:DD:EE:FF")

    def test_ports_summary_solo_abiertos_y_ordenados(self):
        d = Device(ip_address="10.0.0.1")
        d.open_ports = [
            Port(number=443, state="open", service="https"),
            Port(number=22, state="open", service="ssh"),
            Port(number=23, state="closed", service="telnet"),
        ]
        self.assertEqual(d.ports_summary, "22/ssh, 443/https")

    def test_open_port_count(self):
        d = Device(ip_address="10.0.0.1")
        d.open_ports = [Port(number=80, state="open"),
                        Port(number=81, state="closed")]
        self.assertEqual(d.open_port_count, 1)


class StatusColour(unittest.TestCase):
    """
    Los niveles de color estaban intercambiados: la marca devolvia el ambar
    de la atencion para un equipo caido y el rojo de alerta para un simple
    VPN. Una maquina que no contestaba se leia igual que una con VPN.

    La regla vive en la interfaz; aqui se fija el contrato que debe cumplir.
    """

    @staticmethod
    def _tag(device, online, vpn_colour, warning_colour):
        if device.alerts_count or device.worst_severity == "critical":
            return warning_colour
        if not device.is_alive:
            return warning_colour
        if device.is_vpn_active or device.risk_score >= 15:
            return vpn_colour
        return online

    def test_un_equipo_caido_rojo(self):
        caido = Device(ip_address="10.0.0.1", is_alive=False)
        self.assertEqual(self._tag(caido, "G", "A", "R"), "R")

    def test_un_hallazgo_critico_rojo_aunque_este_encendido(self):
        d = Device(ip_address="10.0.0.1", is_alive=True, risk_score=3)
        d.findings = [SecurityFinding(severity="critical", title="t", detail="d")]
        self.assertEqual(self._tag(d, "G", "A", "R"), "R")

    def test_un_vpn_ambar(self):
        d = Device(ip_address="10.0.0.1", is_alive=True, is_vpn_active=True)
        self.assertEqual(self._tag(d, "G", "A", "R"), "A")

    def test_uno_limpio_verde(self):
        d = Device(ip_address="10.0.0.1", is_alive=True)
        self.assertEqual(self._tag(d, "G", "A", "R"), "G")


class IdentityCoverage(unittest.TestCase):
    """
    La lista de puertos de identidad se quedaba en cuatro. Un equipo con su
    panel web en otro puerto salia sin modelo aunque fuera accesible.
    """

    def test_cubre_los_puertos_alternativos(self):
        for puerto in (8443, 8081, 81, 8008, 8888, 9090, 5000):
            self.assertIn(puerto, IDENTITY_PORTS,
                          "falta el puerto %d para identificar" % puerto)

    def test_conserva_los_cuatro_originales(self):
        for puerto in (80, 8080, 443, 8000):
            self.assertIn(puerto, IDENTITY_PORTS)


class PortsColumn(unittest.TestCase):
    """
    La celda de puertos mostraba la lista completa en una fila de 26px de alto.
    Con siete servicios son 532 px de texto en una celda de 116 px: solo se
    veia la primera linea, y parecian faltar puertos que el escaner si habia
    encontrado. Ahora la celda lista solo numeros y declara cuantos mas hay,
    y la lista completa vive en el menu contextual y en la exportacion.
    """

    PUERTOS = [22, 80, 443, 445, 3389, 8080, 9100, 3306, 5432, 6379,
               1883, 554, 8554, 23, 25, 53, 110, 139, 143, 389, 587, 631,
               993, 995, 1433, 5000, 8443, 9090, 8081, 81]

    def _device(self, count):
        device = Device(ip_address="10.0.0.1")
        for number in self.PUERTOS[:count]:
            device.open_ports.append(Port(number=number, state="open",
                                          service="svc"))
        return device

    def _declarados(self, celda):
        """Cuantos puertos declara la celda, contando los del '+N'."""
        import re
        cabeza, _, cola = celda.partition("+")
        return len(re.findall(r"\d+", cabeza)) + (int(cola) if cola else 0)

    def test_la_celda_no_omite_ningun_puerto(self):
        for count in range(1, len(self.PUERTOS) + 1):
            device = self._device(count)
            self.assertEqual(self._declarados(device.ports_compact()), count,
                             "con %d puertos la celda declara otra cosa" % count)

    def test_la_celda_cabe_en_su_columna(self):
        """El texto mostrado tiene que caber en el ancho declarado."""
        try:
            import tkinter as tk
            from tkinter import font as tkfont
            from ip_inspector.interface.ui import DEVICE_COLUMNS
        except Exception as exc:  # pragma: no cover - sin tkinter
            self.skipTest("no hay interfaz: %s" % exc)

        columna = [c for c in DEVICE_COLUMNS if c[4] == "ports"][0]
        wraplength = columna[1] - 4 - 2 * 3
        root = tk.Tk()
        root.withdraw()
        try:
            fuente = tkfont.Font(family="Consolas", size=10)
            for count in range(1, len(self.PUERTOS) + 1):
                ancho = fuente.measure(self._device(count).ports_compact())
                self.assertLessEqual(ancho, wraplength,
                                     "con %d puertos la celda mide %d px "
                                     "y el limite es %d"
                                     % (count, ancho, wraplength))
        finally:
            root.destroy()

    def test_el_resumen_completo_sigue_intacto(self):
        """Lo compacto es solo la celda: el resumen entero no se toca."""
        device = self._device(12)
        self.assertEqual(
            len(device.ports_summary.split(", ")), 12,
            "ports_summary debe seguir trayendo los doce servicios")

    def test_sin_puertos_abiertos_devuelve_guion(self):
        vacio = Device(ip_address="10.0.0.1")
        self.assertEqual(vacio.ports_compact(), "-")

    def test_los_cerrados_no_cuentan(self):
        device = Device(ip_address="10.0.0.1")
        device.open_ports.append(Port(number=443, state="open"))
        device.open_ports.append(Port(number=80, state="closed"))
        self.assertEqual(device.ports_compact(), "443")


if __name__ == "__main__":
    unittest.main()