"""Regresiones del motor: concurrencia del escaner de puertos y rango VPN."""

import inspect
import ipaddress
import unittest

from ip_inspector.core.models import SCAN_PORTS, ScanRequest
from ip_inspector.core.network import NetworkScanner
from ip_inspector.core.utils import (
    MAX_TARGETS,
    _is_sweepable,
    clamp_to_sweep,
    is_ip_in_virtual_subnet,
    plan_targets,
)


class PortScanConcurrency(unittest.TestCase):
    """
    El escaner creaba una tarea por host y cada una recorria sus puertos en
    serie. Un solo worker solo puede sostener un permiso del semaforo, asi que
    la concurrencia era decorativa: un host gastaba un timeout completo por
    puerto cerrado. Con 1024 puertos eran ~20 minutos por maquina; ahora ~6 s.
    """

    def test_una_tarea_por_par_host_puerto(self):
        fuente = inspect.getsource(
            NetworkScanner._scan_ports_concurrently)
        # La forma que hacia todo en serie era iterar puertos DENTRO de un
        # worker por host; ahora la iteracion construye una tarea por par.
        self.assertIn("for port in request.ports", fuente)
        self.assertNotIn("for port_number in request.ports", fuente)

    def test_el_progreso_no_inunda_la_cola(self):
        """Un evento por puerto inundaria la cola que consume la interfaz."""
        fuente = inspect.getsource(
            NetworkScanner._scan_ports_concurrently)
        self.assertIn("completed % 100", fuente)


class ScanPorts(unittest.TestCase):
    """El rango de puertos barrido por defecto."""

    def test_rango_completo(self):
        self.assertEqual(len(SCAN_PORTS), 1024)
        self.assertEqual((SCAN_PORTS[0], SCAN_PORTS[-1]), (1, 1024))

    def test_scan_request_usa_el_rango_completo(self):
        request = ScanRequest(target_range="10.0.0.0/24")
        self.assertEqual(len(request.ports), 1024)
        self.assertTrue(request.scan_ports_enabled)


class VpnSweeping(unittest.TestCase):
    """
    El filtro exigia RFC 1918, asi que una VPN de rango publico (este equipo
    anuncia 26.0.0.0/8) se descartaba entera: elegir el adaptador VPN seguia
    barriendo la LAN de detras.
    """

    def test_vpn_publica_es_barrible(self):
        self.assertTrue(_is_sweepable(ipaddress.ip_network("26.0.0.0/8")))
        self.assertTrue(_is_sweepable(ipaddress.ip_network("100.64.0.0/10")))

    def test_lo_que_no_debe_barrerse(self):
        self.assertFalse(_is_sweepable(ipaddress.ip_network("169.254.0.0/16")))
        self.assertFalse(_is_sweepable(ipaddress.ip_network("127.0.0.0/8")))

    def test_un_slash_ocho_se_acota(self):
        """Un /8 son 16 millones de direcciones: no se puede barragear."""
        acotado = ipaddress.ip_network(
            clamp_to_sweep(ipaddress.ip_network("26.0.0.0/8")))
        self.assertLessEqual(acotado.num_addresses, MAX_TARGETS)
        self.assertGreater(acotado.num_addresses, 1)

    def test_un_rango_normal_no_se_toca(self):
        lan = ipaddress.ip_network("192.168.30.0/23")
        self.assertEqual(clamp_to_sweep(lan), str(lan))

    def test_el_planificador_acepta_la_vpn(self):
        plan = plan_targets(clamp_to_sweep(ipaddress.ip_network("26.0.0.0/8")))
        self.assertFalse(plan.is_empty)

    def test_el_escaneo_no_exige_rfc1918(self):
        fuente = inspect.getsource(NetworkScanner._scannable_networks)
        self.assertNotIn("is_private", fuente)

    def test_la_deteccion_de_vpn_no_revienta(self):
        self.assertFalse(is_ip_in_virtual_subnet("no-es-una-ip"))


if __name__ == "__main__":
    unittest.main()