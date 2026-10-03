"""Regresiones del motor: concurrencia del escaner de puertos y rango VPN."""

import inspect
import ipaddress
import unittest

from ip_inspector.core import network
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
    puerto cerrado. Con 1024 puertos eran ~20 minutos por maquina.

    La segunda version usaba asyncio con una tarea por par, lo que duplicaba el
    tiempo: ``connect`` libera el GIL, asi que un pool de hilos rinde el doble
    que el bucle de eventos para esta carga. Medido aqui: 481 sondas/s con
    asyncio frente a 4485 con hilos.
    """

    def test_una_sonda_por_par_host_puerto(self):
        fuente = inspect.getsource(NetworkScanner._scan_ports_threaded)
        # La forma que hacia todo en serie era iterar puertos DENTRO de un
        # worker por host; ahora la iteracion encola un par por trabajo.
        self.assertIn("for port in request.ports", fuente)
        self.assertNotIn("for port_number in request.ports", fuente)

    def test_usa_hilos_y_no_asyncio(self):
        fuente = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("ThreadPoolExecutor", fuente)
        self.assertNotIn("asyncio", fuente)

    def test_el_progreso_no_inunda_la_cola(self):
        """Un evento por puerto inundaria la cola que consume la interfaz."""
        fuente = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("completed % 100", fuente)

    def test_el_tope_no_supera_las_sondas_reales(self):
        """Abrir 2000 hilos para 300 sondas desperdicia memoria sin ganar nada."""
        fuente = inspect.getsource(NetworkScanner._scan_ports_threaded)
        self.assertIn("min(request.concurrency, total)", fuente)

    def test_los_valores_por_defecto_son_los_rapidos(self):
        """Regresion: 1.0s y 500 sondas eran la configuracion lenta."""
        request = ScanRequest(target_range="10.0.0.0/24")
        self.assertLessEqual(request.port_timeout, 0.5)
        self.assertGreaterEqual(request.concurrency, 2000)


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


class AbsorbeArpTrasSondeo(unittest.TestCase):
    """
    La instantanea ARP se tomaba ANTES del sondeo de alcance, pero es el
    sondeo justamente lo que hace que el sistema resuelva cada host a una MAC.
    Esas resoluciones llegan a la tabla de vecinos despues de la foto, asi que
    los hosts que el escaner tocaba por primera vez descartaban su MAC y la
    columna salia en blanco pese a que el sistema ya la conocia.
    """

    def setUp(self):
        self.scanner = NetworkScanner.__new__(NetworkScanner)
        self.originals = {
            "read_arp_cache": network.read_arp_cache,
            "is_elevated": network.is_elevated,
            "supports_layer2": network.supports_layer2,
        }

    def tearDown(self):
        network.read_arp_cache = self.originals["read_arp_cache"]
        network.is_elevated = self.originals["is_elevated"]
        network.supports_layer2 = self.originals["supports_layer2"]

    def _sin_capa2(self, cache):
        network.is_elevated = lambda: False
        network.supports_layer2 = lambda: False
        network.read_arp_cache = lambda: dict(cache)

    def test_recupera_la_mac_que_enseno_el_sondeo(self):
        # El host estaba en la foto vacia, pero el sondeo lo resolvio.
        self._sin_capa2({"192.168.30.7": "aa:bb:cc:dd:ee:01"})
        tabla: dict[str, str] = {}
        alcanzables = {"192.168.30.7": (1.0, None)}

        NetworkScanner._absorb_arp_after_probe(self.scanner, tabla, alcanzables)

        self.assertEqual(tabla.get("192.168.30.7"), "aa:bb:cc:dd:ee:01")

    def test_no_pisa_una_mac_ya_conocida(self):
        self._sin_capa2({"192.168.30.7": "aa:bb:cc:dd:ee:01"})
        tabla = {"192.168.30.7": "11:22:33:44:55:66"}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, tabla, {"192.168.30.7": (1.0, None)})

        self.assertEqual(tabla["192.168.30.7"], "11:22:33:44:55:66")

    def test_sin_entrada_sigue_sin_mac(self):
        # Un host inalcanzable para ARP se queda sin MAC; eso es correcto.
        self._sin_capa2({})
        tabla: dict[str, str] = {}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, tabla, {"192.168.30.7": (1.0, None)})

        self.assertEqual(tabla, {})

    def test_con_capa2_no_relee_la_tabla(self):
        # Con L2 el barrido ARP ya contesto por todos: releer no aportaria nada.
        network.is_elevated = lambda: True
        network.supports_layer2 = lambda: True
        llamadas = []

        def cache():
            llamadas.append(1)
            return {"192.168.30.7": "aa:bb:cc:dd:ee:01"}

        network.read_arp_cache = cache
        tabla: dict[str, str] = {}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, tabla, {"192.168.30.7": (1.0, None)})

        self.assertEqual(tabla, {})
        self.assertEqual(llamadas, [])

    def test_una_sola_lectura_de_la_tabla(self):
        """ releer por cada host reenumeraria todas las interfaces 200 veces."""
        self._sin_capa2({})
        llamadas = []

        def cache():
            llamadas.append(1)
            return {}

        network.read_arp_cache = cache
        alcanzables = {"192.168.30.%d" % n: (1.0, None) for n in range(2, 60)}

        NetworkScanner._absorb_arp_after_probe(
            self.scanner, {}, alcanzables)

        self.assertEqual(len(llamadas), 1)


if __name__ == "__main__":
    unittest.main()