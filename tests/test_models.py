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


if __name__ == "__main__":
    unittest.main()