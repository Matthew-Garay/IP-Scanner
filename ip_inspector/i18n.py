"""Bilingual catalogue (English / Spanish) for IP Inspector.

Design
------
* ``CATALOG`` maps a stable key to both languages. Keys never change, so a
  missing translation degrades to the key itself rather than crashing.
* The active language is process-global, which suits a single-window desktop
  app and keeps call sites free of plumbing.
* ``translate_line`` handles the free-form output produced by ``tools`` and
  ``audit``. Those modules return human sentences rather than keys, so we
  normalise them at the rendering boundary instead of threading a key
  through every return type.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

Language = Literal["en", "es"]

DEFAULT_LANGUAGE: Language = "en"
LANGUAGES: tuple[Language, ...] = ("en", "es")

#: Human labels for the switcher.
LANGUAGE_NAMES: dict[Language, str] = {"en": "English", "es": "Espanol"}

_current: Language = DEFAULT_LANGUAGE


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

CATALOG: dict[str, dict[str, str]] = {
    # -- chrome --------------------------------------------------------
    "app.tagline": {
        "en": "Network discovery  ·  Port analysis  ·  Security auditing",
        "es": "Descubrimiento de red  ·  Analisis de puertos  ·  Auditoria de seguridad",
    },
    "app.language": {"en": "Language", "es": "Idioma"},
    # -- dashboard -----------------------------------------------------
    "kpi.devices": {"en": "Devices", "es": "Equipos"},
    "kpi.routers": {"en": "Routers / GW", "es": "Routers / GW"},
    "kpi.ports": {"en": "Open ports", "es": "Puertos"},
    "kpi.vpn": {"en": "VPN / Tunnel", "es": "VPN / Tunel"},
    "kpi.risk": {"en": "At risk (>=15)", "es": "En riesgo (>=15)"},
    # -- tabs ----------------------------------------------------------
    "tab.scan": {"en": "Network Scan", "es": "Escaneo de red"},
    "tab.audit": {"en": "Security Audit", "es": "Auditoria"},
    "tab.tools": {"en": "Tools", "es": "Herramientas"},
    "tab.quick": {"en": "Quick Tools", "es": "Utilidades"},
    "tab.inventory": {"en": "Inventory", "es": "Inventario"},
    "tab.monitor": {"en": "Monitor", "es": "Monitor"},
    # -- monitor --------------------------------------------------------
    "mon.add": {"en": "Add host", "es": "Anadir host"},
    "mon.start": {"en": "Start monitoring", "es": "Iniciar monitor"},
    "mon.stop": {"en": "Stop", "es": "Detener"},
    "mon.remove": {"en": "Remove", "es": "Quitar"},
    "mon.clear": {"en": "Clear log", "es": "Limpiar registro"},
    "mon.hint": {"en": "IP or host to watch", "es": "IP o host a vigilar"},
    "mon.label": {"en": "Label", "es": "Etiqueta"},
    "mon.port": {"en": "Port", "es": "Puerto"},
    "mon.interval": {"en": "Interval", "es": "Intervalo"},
    "mon.col.status": {"en": "Status", "es": "Estado"},
    "mon.col.host": {"en": "Host", "es": "Host"},
    "mon.col.latency": {"en": "Latency", "es": "Latencia"},
    "mon.col.avg": {"en": "Avg", "es": "Media"},
    "mon.col.uptime": {"en": "Uptime", "es": "Disponib."},
    "mon.col.checks": {"en": "Checks", "es": "Pruebas"},
    "mon.col.since": {"en": "Since", "es": "Desde"},
    "mon.col.spark": {"en": "Trend", "es": "Tendencia"},
    "mon.log": {"en": "Alert log", "es": "Registro de alertas"},
    "mon.log.empty": {
        "en": "No alerts yet. Add a host and start monitoring.",
        "es": "Sin alertas. Anade un host e inicia el monitor.",
    },
    "mon.watching": {"en": "Watching {count} hosts", "es": "Vigilando {count} hosts"},
    "mon.stopped": {"en": "Monitoring stopped", "es": "Monitor detenido"},
    "mon.added": {"en": "{ip} added to the monitor", "es": "{ip} anadido al monitor"},
    "ctx.monitor": {"en": "Add to monitor", "es": "Anadir al monitor"},
    # -- inventory -----------------------------------------------------
    "inv.new": {"en": "NEW", "es": "NUEVO"},
    "inv.identity": {"en": "CHANGED", "es": "CAMBIADO"},
    "inv.vendor": {"en": "VENDOR", "es": "FABRICANTE"},
    "inv.missing": {"en": "MISSING", "es": "AUSENTE"},
    "inv.returning": {"en": "RETURN", "es": "REGRESO"},
    "inv.known": {"en": "KNOWN", "es": "CONOCIDO"},
    "inv.mac": {"en": "MAC", "es": "MAC"},
    "inv.detail": {"en": "Detail", "es": "Detalle"},
    "inv.vendorcol": {"en": "Vendor", "es": "Marca"},
    "inv.typecol": {"en": "Type", "es": "Tipo"},
    "inv.firstseen": {"en": "First seen", "es": "Visto por 1a"},
    "inv.empty": {
        "en": "Run a scan to compare the network against the stored inventory",
        "es": "Ejecuta un escaneo para comparar la red con el inventario",
    },
    "inv.baseline": {
        "en": "{count} devices in the baseline",
        "es": "{count} equipos en el inventario",
    },
    "inv.summary": {
        "en": "{new} new  ·  {changed} changed  ·  {missing} missing  ·  baseline {total}",
        "es": "{new} nuevos  ·  {changed} cambiados  ·  {missing} ausentes  ·  base {total}",
    },
    "inv.approve": {"en": "Approve selected", "es": "Aprobar seleccionado"},
    "inv.forget": {"en": "Forget selected", "es": "Olvidar seleccionado"},
    "inv.reset": {"en": "Reset baseline", "es": "Reiniciar inventario"},
    "inv.export": {"en": "Export report", "es": "Exportar informe"},
    "inv.approved": {"en": "{mac} marked as approved", "es": "{mac} marcado como aprobado"},
    "inv.forgotten": {"en": "{mac} removed from the inventory", "es": "{mac} eliminado del inventario"},
    "inv.reset.done": {"en": "Inventory cleared", "es": "Inventario vaciado"},
    "inv.reset.ask": {
        "en": "This deletes every stored device and uses the next scan as the new baseline. Continue?",
        "es": "Se borraran todos los equipos guardados y el proximo escaneo sera la nueva base. Continuar?",
    },
    "inv.saved": {"en": "Report written to {path}", "es": "Informe guardado en {path}"},
    # -- inputs --------------------------------------------------------
    "label.range": {"en": "Target range", "es": "Rango"},
    "label.ports": {"en": "Ports", "es": "Puertos"},
    "ports.count": {"en": "{count} ports to scan", "es": "{count} puertos a escanear"},
    "ports.empty": {
        "en": "Leave empty for the common ports",
        "es": "Vacio para usar los puertos comunes",
    },
    "ports.invalid": {
        "en": "Not a port: {items}",
        "es": "No es un puerto: {items}",
    },
    "label.target": {"en": "Target", "es": "Objetivo"},
    "label.filter": {"en": "Filter", "es": "Filtro"},
    "ph.range": {"en": "192.168.1.0/24", "es": "192.168.1.0/24"},
    "ph.ports": {"en": "22,80,443,445,3389", "es": "22,80,443,445,3389"},
    "ph.audit": {
        "en": "IP, hostname or http(s)://url",
        "es": "IP, host o http(s)://url",
    },
    "ph.tool": {"en": "IP, hostname or CIDR", "es": "IP, host o CIDR"},
    "ph.filter": {
        "en": "ip, hostname, vendor, type or port",
        "es": "ip, nombre, marca, tipo o puerto",
    },
    # -- buttons -------------------------------------------------------
    "btn.start": {"en": "Start Scan", "es": "Iniciar"},
    "btn.stop": {"en": "Stop", "es": "Detener"},
    "btn.audit.target": {"en": "Audit Target", "es": "Auditar objetivo"},
    "btn.audit.selected": {"en": "Audit Selected", "es": "Auditar equipo"},
    "btn.audit.all": {"en": "Audit All", "es": "Auditar todos"},
    "btn.clear": {"en": "Clear", "es": "Limpiar"},
    "sw.ports": {"en": "Scan ports", "es": "Escanear puertos"},
    # -- device table --------------------------------------------------
    "col.ip": {"en": "IP", "es": "IP"},
    "col.status": {"en": "Status", "es": "Estado"},
    "col.hostname": {"en": "Hostname", "es": "Nombre"},
    "col.mac": {"en": "MAC", "es": "MAC"},
    "col.vendor": {"en": "Vendor", "es": "Marca"},
    "col.type": {"en": "Type", "es": "Tipo"},
    # The pictogram column carries no label: it only repeats the type beside
    # the icon, so an empty header keeps the column from looking like a second
    # field to read.
    "col.icon": {"en": "", "es": ""},
    "col.vpn": {"en": "VPN", "es": "VPN"},
    "col.risk": {"en": "Risk", "es": "Riesgo"},
    "col.ports": {"en": "Ports", "es": "Puertos"},
    # -- findings table ------------------------------------------------
    "col.severity": {"en": "Severity", "es": "Severidad"},
    "col.level": {"en": "Level", "es": "Nivel"},
    "col.finding": {"en": "Finding", "es": "Hallazgo"},
    "col.detail": {"en": "Detail", "es": "Detalle"},
    "col.target": {"en": "Target", "es": "Objetivo"},
    # -- runtime messages ----------------------------------------------
    "status.ready": {"en": "Ready", "es": "Listo"},
    "status.scanning": {"en": "Scanning...", "es": "Escaneando..."},
    # Live readout in the status strip: how far along, and how many of how many.
    "status.progress": {
        "en": "{percent}%  ·  {done} of {total}",
        "es": "{percent}%  ·  {done} de {total}",
    },
    # Counter of what the sweep has actually turned up.
    "status.found": {
        "en": "{count} active devices",
        "es": "{count} dispositivos activos",
    },
    "status.shown": {"en": "{count} shown", "es": "{count} mostrados"},
    "status.sorted": {"en": "sorted by {column} {arrow}", "es": "orden por {column} {arrow}"},
    "status.findings": {
        "en": "{count} findings   ·   {high} critical or high   ·   risk score {score}/100",
        "es": "{count} hallazgos   ·   {high} criticos o altos   ·   riesgo {score}/100",
    },
    "status.audit.done": {"en": "Audit complete", "es": "Auditoria completada"},
    "status.stopping": {"en": "Stopping...", "es": "Deteniendo..."},
    "status.error": {"en": "Error: {message}", "es": "Error: {message}"},
    "hint.range": {"en": "Enter a target range first", "es": "Introduce un rango primero"},
    "hint.target": {"en": "Enter a target to audit", "es": "Introduce un objetivo"},
    "hint.tool": {"en": "Enter a target first", "es": "Introduce un objetivo"},
    "hint.busy": {
        "en": "Wait for the current operation to finish",
        "es": "Espera a que termine la operacion actual",
    },
    "hint.scanfirst": {"en": "Run a scan first", "es": "Ejecuta un escaneo primero"},
    "hint.scanfirst.device": {
        "en": "Run a scan first, then audit a device",
        "es": "Ejecuta un escaneo y luego audita un equipo",
    },
    "empty.hint": {
        "en": "Run a scan to populate the inventory",
        "es": "Ejecuta un escaneo para llenar el inventario",
    },
    # -- scanner phases ------------------------------------------------
    "phase.discovery": {"en": "Discovery", "es": "Descubrimiento"},
    "phase.ports": {"en": "Ports", "es": "Puertos"},
    "phase.finished": {"en": "Finished", "es": "Terminado"},
    "phase.cancelled": {"en": "Cancelled", "es": "Cancelado"},
    "phase.device": {"en": "Device", "es": "Equipo"},
    "phase.banner": {"en": "Banner", "es": "Banner"},
    "phase.analysis": {"en": "Analysis", "es": "Analisis"},
    "phase.vpn": {"en": "VPN", "es": "VPN"},
    "msg.devices.found": {"en": "{count} devices found", "es": "{count} equipos encontrados"},
    "msg.stopped": {"en": "Scan stopped by user", "es": "Escaneo detenido por el usuario"},
    "msg.invalid.range": {"en": "Invalid or empty target range", "es": "Rango no valido o vacio"},
    "msg.scan.error": {"en": "Unexpected scan error", "es": "Error inesperado en el escaneo"},
    "msg.scanning.addrs": {"en": "Scanning {count} addresses", "es": "Escaneando {count} direcciones"},
    "msg.probing": {"en": "Probing {count} ports", "es": "Probando {count} puertos"},
    "msg.portscan.done": {"en": "Port scan complete", "es": "Escaneo de puertos completado"},
    # -- device state --------------------------------------------------
    "state.online": {"en": "Online", "es": "En linea"},
    "state.offline": {"en": "Offline", "es": "Desconectado"},
    "value.unknown.vendor": {"en": "Unknown vendor", "es": "Marca desconocida"},
    "value.unknown": {"en": "Unknown", "es": "Desconocido"},
    "value.vpn": {"en": "VPN", "es": "VPN"},
    # -- device types --------------------------------------------------
    "type.router": {"en": "Router", "es": "Router"},
    "type.windows": {"en": "Windows PC", "es": "PC Windows"},
    "type.linux": {"en": "Linux Server", "es": "Servidor Linux"},
    "type.printer": {"en": "Printer", "es": "Impresora"},
    "type.iot": {"en": "IoT Device", "es": "Dispositivo IoT"},
    "type.apple": {"en": "Apple Device", "es": "Dispositivo Apple"},
    "type.raspberry": {"en": "Raspberry Pi", "es": "Raspberry Pi"},
    "type.camera": {"en": "IP Camera", "es": "Camara IP"},
    "type.server": {"en": "Server", "es": "Servidor"},
    "type.netdev": {"en": "Network Device", "es": "Equipo de red"},
    "type.mobile": {"en": "Mobile / Tablet", "es": "Movil / Tablet"},
    # -- severity ------------------------------------------------------
    "sev.critical": {"en": "CRIT", "es": "CRIT"},
    "sev.high": {"en": "HIGH", "es": "ALTO"},
    "sev.medium": {"en": "MED", "es": "MED"},
    "sev.low": {"en": "LOW", "es": "BAJO"},
    "sev.info": {"en": "INFO", "es": "INFO"},
    # -- tool names ----------------------------------------------------
    "tool.ping": {"en": "Ping", "es": "Ping"},
    "tool.traceroute": {"en": "Traceroute", "es": "Traza"},
    "tool.whois": {"en": "WHOIS", "es": "WHOIS"},
    "tool.dns": {"en": "DNS", "es": "DNS"},
    "tool.ptr": {"en": "PTR", "es": "PTR"},
    "tool.subnet": {"en": "Subnet", "es": "Subred"},
    "tool.zone": {"en": "Zone Xfer", "es": "Transferencia"},
    "tool.dmarc": {"en": "SPF/DMARC", "es": "SPF/DMARC"},
    "tool.exposure": {"en": "Local exposure", "es": "Exposicion local"},
    "tool.listening": {"en": "Listening ports", "es": "Puertos en escucha"},
    "tool.http": {"en": "HTTP audit", "es": "Auditoria HTTP"},
    "tool.tls": {"en": "TLS certificate", "es": "Certificado TLS"},
    "tool.ok": {"en": "OK", "es": "OK"},
    "tool.error": {"en": "ERROR", "es": "ERROR"},
    # -- quick tools ----------------------------------------------------
    "qt.trace.title": {
        "en": "Traceroute (visual path)",
        "es": "Traceroute (ruta visual)",
    },
    "qt.subnet.title": {
        "en": "Subnet calculator (CIDR)",
        "es": "Calculadora de subredes (CIDR)",
    },
    "qt.lookup.title": {"en": "DNS lookup / WHOIS", "es": "Consulta DNS / WHOIS"},
    "qt.trace.hops": {"en": "Max hops", "es": "Saltos"},
    "qt.trace.split": {"en": "Split into", "es": "Dividir en"},
    "qt.trace.running": {
        "en": "Tracing the path to {target}...",
        "es": "Trazando la ruta hacia {target}...",
    },
    "qt.trace.summary": {
        "en": "{hops} hops   ·   {answered} answered   ·   average {average} ms",
        "es": "{hops} saltos   ·   {answered} responden   ·   media {average} ms",
    },
    "qt.trace.empty": {
        "en": "Run a trace to plot the path to a destination",
        "es": "Ejecuta una traza para dibujar la ruta a un destino",
    },
    "qt.trace.noreply": {"en": "no response", "es": "sin respuesta"},
    "qt.trace.dest": {"en": "destination", "es": "destino"},
    "qt.copied": {
        "en": "Path copied to the clipboard",
        "es": "Ruta copiada al portapapeles",
    },
    "qt.subnet.invalid": {
        "en": "That is not a valid CIDR block",
        "es": "Ese no es un bloque CIDR valido",
    },
    "qt.subnet.plan.hint": {
        "en": "Pick a split size to divide this block into equal subnets",
        "es": "Elige un tamano para dividir el bloque en subredes iguales",
    },
    "qt.lookup.empty": {
        "en": "Resolve a domain or check the owner of an IP",
        "es": "Resuelve un dominio o consulta el titular de una IP",
    },
    # -- live latency graph ----------------------------------------------
    "qt.latency.title": {
        "en": "Latency (live ping)",
        "es": "Latencia (ping en vivo)",
    },
    "qt.latency.start": {"en": "Start", "es": "Iniciar"},
    "qt.latency.stop": {"en": "Stop", "es": "Detener"},
    "qt.latency.every": {"en": "Every", "es": "Cada"},
    "qt.latency.running": {
        "en": "Pinging {host} every {interval:g}s",
        "es": "Haciendo ping a {host} cada {interval:g}s",
    },
    "qt.latency.stopped": {
        "en": "Latency capture stopped",
        "es": "Captura de latencia detenida",
    },
    "qt.latency.idle": {
        "en": "Enter a host and press Start to plot its latency over time",
        "es": "Introduce un host y pulsa Iniciar para dibujar su latencia",
    },
    "qt.latency.lost": {
        "en": "{host} has not answered a single probe yet",
        "es": "{host} todavia no ha respondido a ningun sondeo",
    },
    "qt.latency.window": {
        "en": "{count} probes   ·   loss {loss:g} %",
        "es": "{count} sondeos   ·   perdida {loss:g} %",
    },
    "qt.latency.last": {"en": "Last", "es": "Ultima"},
    "qt.latency.min": {"en": "Min", "es": "Min"},
    "qt.latency.avg": {"en": "Avg", "es": "Media"},
    "qt.latency.max": {"en": "Max", "es": "Max"},
    "qt.latency.jitter": {"en": "Jitter", "es": "Variacion"},
    "qt.latency.loss": {"en": "Loss", "es": "Perdida"},
    "btn.trace": {"en": "Trace", "es": "Trazar"},
    "btn.calculate": {"en": "Calculate", "es": "Calcular"},
    "btn.resolve": {"en": "Resolve", "es": "Resolver"},
    "btn.summary": {"en": "Overview", "es": "Resumen"},
    "btn.whois": {"en": "WHOIS", "es": "WHOIS"},
    "btn.copy.path": {"en": "Copy path", "es": "Copiar ruta"},
    "ph.host": {"en": "IP or hostname", "es": "IP o nombre de host"},
    "ph.cidr": {"en": "192.168.1.0/24", "es": "192.168.1.0/24"},
    "ph.domain": {"en": "domain.com or 1.2.3.4", "es": "dominio.com o 1.2.3.4"},
    # -- subnet calculator ----------------------------------------------
    "sub.network": {"en": "Network", "es": "Red"},
    "sub.mask": {"en": "Subnet mask", "es": "Mascara de subred"},
    "sub.wildcard": {"en": "Wildcard mask", "es": "Mascara wildcard"},
    "sub.broadcast": {"en": "Broadcast", "es": "Broadcast"},
    "sub.first": {"en": "First host", "es": "Primer host"},
    "sub.last": {"en": "Last host", "es": "Ultimo host"},
    "sub.total": {"en": "Addresses", "es": "Direcciones"},
    "sub.usable": {"en": "Usable hosts", "es": "Hosts utilizables"},
    "sub.scope": {"en": "Scope", "es": "Alcance"},
    "sub.private": {"en": "private", "es": "privada"},
    "sub.public": {"en": "public", "es": "publica"},
    # -- WHOIS summary ---------------------------------------------------
    "qt.whois.domain": {"en": "Domain", "es": "Dominio"},
    "qt.whois.org": {"en": "Organisation", "es": "Organizacion"},
    "qt.whois.country": {"en": "Country", "es": "Pais"},
    "qt.whois.created": {"en": "Created", "es": "Creado"},
    "qt.whois.updated": {"en": "Updated", "es": "Actualizado"},
    "qt.whois.expires": {"en": "Expires", "es": "Expira"},
    "qt.whois.status": {"en": "Status", "es": "Estado"},
    "qt.whois.registrar": {"en": "Registrar", "es": "Registrador"},
    "qt.whois.abuse": {"en": "Abuse contact", "es": "Contacto de abuso"},
    "qt.whois.nameservers": {"en": "Name servers", "es": "Servidores de nombre"},
    "col.model": {"en": "Model", "es": "Modelo"},
    "col.ttl": {"en": "TTL", "es": "TTL"},
    "col.latency": {"en": "Ping", "es": "Latencia"},
    "col.method": {"en": "Method", "es": "Metodo"},
    "phase.models": {"en": "Models", "es": "Modelos"},
    "msg.identifying": {
        "en": "Identifying {count} devices",
        "es": "Identificando {count} equipos",
    },
    "ctx.export": {"en": "Export row", "es": "Exportar fila"},
    "msg.exported": {
        "en": "Row exported to {path}",
        "es": "Fila exportada a {path}",
    },
    # -- scan profiles ---------------------------------------------------
    # -- target range ---------------------------------------------------
    "status.matching": {"en": "{shown} of {total} match", "es": "{shown} de {total} coinciden"},
    "net.gateway": {
        "en": "Gateway {gateway}",
        "es": "Puerta de enlace {gateway}",
    },
    "wol.sent": {
        "en": "Wake-on-LAN packet sent to {mac}",
        "es": "Paquete Wake-on-LAN enviado a {mac}",
    },
    "export.csv": {"en": "CSV", "es": "CSV"},
    "export.json": {"en": "JSON", "es": "JSON"},
    "export.done": {
        "en": "{count} devices exported to {path}",
        "es": "{count} dispositivos exportados a {path}",
    },
    "target.count": {"en": "{count} addresses", "es": "{count} direcciones"},
    "target.excluded": {
        "en": "{count} reserved dropped (network and broadcast)",
        "es": "{count} reservadas descartadas (red y broadcast)",
    },
    "target.capped": {
        "en": "{asked} requested: only the first {limit} will be scanned",
        "es": "{asked} solicitadas: solo se escanearan las {limit} primeras",
    },
    "target.problem": {
        "en": "Not a valid block: {items}",
        "es": "No es un bloque valido: {items}",
    },
    "target.empty": {
        "en": "Type a block (192.168.1.0/24), a span (10-50) or both",
        "es": "Escribe un bloque (192.168.1.0/24), un rango (10-50) o ambos",
    },
    "target.ignoring": {
        "en": "ignoring {items}",
        "es": "se ignoran {items}",
    },
    "target.partial": {
        "en": "Scanning what parsed; ignored: {items}",
        "es": "Escaneando lo valido; se ignoran: {items}",
    },
    # -- interface selector -----------------------------------------------
    "iface.auto.short": {"en": "Auto", "es": "Auto"},
    "iface.caption": {"en": "Interface", "es": "Interfaz"},
    "iface.auto": {
        "en": "Automatic (let the OS choose)",
        "es": "Automatica (que elija el SO)",
    },
    "iface.virtual": {"en": "virtual", "es": "virtual"},
    "iface.down": {"en": "disconnected", "es": "sin conectar"},
    "iface.selected": {
        "en": "Scanning from {name} ({network})",
        "es": "Escaneando desde {name} ({network})",
    },
    "iface.gone": {
        "en": "Adapter {name} is no longer connected",
        "es": "El adaptador {name} ya no esta conectado",
    },
    "iface.unusable": {
        "en": "{name} cannot host a scan: it has no routable IPv4 subnet",
        "es": "{name} no admite un escaneo: no tiene una subred IPv4 enrutable",
    },
    "exp.title.port": {"en": "Port {port} open", "es": "Puerto {port} abierto"},
    "exp.title.port_public": {
        "en": "Port {port} open on a public address",
        "es": "Puerto {port} abierto en una direccion publica",
    },
    "exp.reason.telnet": {
        "en": "Telnet is obsolete: user name, password and the whole session travel in clear text, and nothing is ever written to a log.",
        "es": "Telnet esta obsoleto: usuario, contrasena y sesion completa viajan en texto claro y nunca quedan registrados.",
    },
    "exp.reason.ssh": {
        "en": "A remote shell is reachable. On this host it is the usual entry point for password attacks; restrict it to a VPN or an allow list.",
        "es": "Hay una shell remota accesible. En este equipo es la puerta habitual a los ataques por contrasena; restrinjela a VPN o lista blanca.",
    },
    "exp.reason.rdp": {
        "en": "Remote Desktop is reachable, the most brute-forced service there is. Network Level Authentication plus a lockout policy is the minimum.",
        "es": "Escritorio remoto accesible, el servicio mas atacado por fuerza bruta. NLA y una politica de bloqueo son el minimo.",
    },
    "exp.reason.vnc": {
        "en": "VNC is usually a thin password over an unencrypted channel: a remote desktop with no confidentiality at all.",
        "es": "VNC suele ser una contrasena corta sobre un canal sin cifrar: un escritorio remoto sin ninguna confidencialidad.",
    },
    "exp.reason.ftp": {
        "en": "FTP sends credentials in clear text. Move to SFTP, or at least to FTPS.",
        "es": "FTP envia las contrasenas en texto claro. Migra a SFTP o, al menos, a FTPS.",
    },
    "exp.reason.tftp": {
        "en": "TFTP has no authentication at all: anyone can read or overwrite files on the device.",
        "es": "TFTP no tiene autenticacion: cualquiera puede leer o sobrescribir ficheros del equipo.",
    },
    "exp.reason.smb": {
        "en": "SMB shares are the usual entry point for ransomware and lateral movement. Keep them inside the LAN and require modern SMB.",
        "es": "Los recursos SMB son la puerta habitual del ransomware y del movimiento lateral. Limitelos a la LAN y exija SMB moderno.",
    },
    "exp.reason.netbios": {
        "en": "The legacy NetBIOS session service is enabled, which is what WannaCry and EternalBlue used to spread.",
        "es": "El servicio NetBIOS heredado esta activo, el mismo que usaron WannaCry y EternalBlue para propagarse.",
    },
    "exp.reason.nfs": {
        "en": "NFS exports a filesystem to whoever asks, often with host-based trust that any spoofed address satisfies.",
        "es": "NFS exporta un sistema de ficheros a quien lo pida, a menudo con confianza por IP que cualquier suplantacion satisface.",
    },
    "exp.reason.db": {
        "en": "A database engine is reachable from the network. If it listens on 0.0.0.0 it usually accepts connections without a password.",
        "es": "Un motor de base de datos es accesible desde la red. Si escucha en 0.0.0.0 suele aceptar conexiones sin contrasena.",
    },
    "exp.reason.cache": {
        "en": "A cache or queue without authentication. Redis and Memcached have no protocol-level auth at all, and both have known remote-code-execution paths.",
        "es": "Cache o cola sin autenticacion. Redis y Memcached no tienen auth a nivel de protocolo y ambos tienen rutas conocidas de ejecucion remota.",
    },
    "exp.reason.rsh": {
        "en": "rexec and rlogin authenticate by source address alone: anyone who can spoof an IP on the path gets a shell.",
        "es": "rexec y rlogin autentican solo por direccion de origen: quien suplante una IP en el camino obtiene una shell.",
    },
    "exp.reason.syslog": {
        "en": "A syslog listener without TLS leaks the logs of every device that reports to it, and often accepts forged entries.",
        "es": "Un syslog sin TLS filtra los registros de todos los equipos que reportan a el, y suele aceptar entradas falsificadas.",
    },
    "exp.reason.rsync": {
        "en": "rsync is usually exported with a module name and no password, which turns it into a read or write filesystem.",
        "es": "rsync suele exportarse con nombre de modulo y sin contrasena, lo que lo convierte en un sistema de ficheros de lectura o escritura.",
    },
    "exp.reason.proxy": {
        "en": "An open proxy can be used to reach the rest of the network from outside and to disguise the origin of traffic.",
        "es": "Un proxy abierto permite alcanzar el resto de la red desde fuera y disfrazar el origen del trafico.",
    },
    "exp.reason.other": {"en": "{reason}", "es": "{reason}"},
    "exp.admin.gateway.title": {
        "en": "Remote administration on a gateway",
        "es": "Administracion remota en un router",
    },
    "exp.admin.gateway.detail": {
        "en": "This is the device that routes the whole network, and its console is the crown jewel: {ports} accept remote sessions.",
        "es": "Es el equipo que enruta toda la red y su consola es el mayor objetivo: {ports} aceptan sesiones remotas.",
    },
    "exp.admin.exposed.title": {
        "en": "Remote administration on {device_type}",
        "es": "Administracion remota en {device_type}",
    },
    "exp.admin.exposed.detail": {
        "en": "One of the device types brute-forced first because their firmware is rarely patched ({ports}).",
        "es": "De los tipos que primero reciben fuerza bruta porque su firmware casi nunca se parchea ({ports}).",
    },
    "exp.combo.telnet_ssh.title": {
        "en": "Telnet open despite SSH",
        "es": "Telnet abierto pese a SSH",
    },
    "exp.combo.telnet_ssh.detail": {
        "en": "Telnet is still enabled although SSH is available: the obsolete path is the one an attacker tries first.",
        "es": "Telnet sigue activo aunque haya SSH disponible: la via obsoleta es la primero que probara un atacante.",
    },
    "exp.combo.netbios.title": {
        "en": "SMB with legacy NetBIOS",
        "es": "SMB con NetBIOS heredado",
    },
    "exp.combo.netbios.detail": {
        "en": "SMB is served together with the legacy NetBIOS session service, which keeps the old attack surface alive.",
        "es": "SMB se sirve junto al servicio NetBIOS heredado, lo que mantiene viva la antigua superficie de ataque.",
    },
    "exp.combo.smb_rdp.title": {
        "en": "SMB and RDP open together",
        "es": "SMB y RDP abiertos a la vez",
    },
    "exp.combo.smb_rdp.detail": {
        "en": "A stolen credential gets file access over SMB first and an interactive session over RDP second, which is a complete remote takeover.",
        "es": "Una contrasena robada da acceso a ficheros por SMB y despues sesion interactiva por RDP: control remoto completo.",
    },
    "exp.public.title": {
        "en": "Public address with management services exposed",
        "es": "Direccion publica con servicios de administracion expuestos",
    },
    "exp.public.detail": {
        "en": "This host is routable on the internet ({ports}). Anything open on it is scanned continuously, so treat every port below as public.",
        "es": "Este equipo es enrutable en internet ({ports}). Todo lo que tenga abierto se escanea de forma continua, asi que trata cada puerto como publico.",
    },
    "btn.audit.quick": {"en": "Quick check", "es": "Chequeo rapido"},
    "status.audit.quick": {
        "en": "{count} hosts checked without touching the network",
        "es": "{count} equipos revisados sin tocar la red",
    },
    "col.alerts": {"en": "Alerts", "es": "Alertas"},
    "profile.quick": {"en": "Quick", "es": "Rapido"},
    "profile.deep": {"en": "Deep", "es": "Profundo"},
    "profile.iot": {"en": "IoT / Cameras", "es": "IoT / Camaras"},
    "profile.custom": {"en": "Custom", "es": "Personalizado"},
    "profile.hint": {"en": "Scan profile", "es": "Perfil de escaneo"},
    "profile.quick.desc": {
        "en": "ARP sweep plus the four ports that answer \"is this host up\"",
        "es": "Barrido ARP mas los cuatro puertos que dicen \"esta vivo\"",
    },
    "profile.deep.desc": {
        "en": "Full range 1-1024 with deep banner grabbing. Slow, but exhaustive",
        "es": "Rango completo 1-1024 con banners avanzados. Lento pero exhaustivo",
    },
    "profile.iot.desc": {
        "en": "RTSP/ONVIF/UPnP ports; identifies camera make and model",
        "es": "Puertos RTSP/ONVIF/UPnP; identifica marca y modelo de la camara",
    },
    "profile.ports": {"en": "Ports: {ports}", "es": "Puertos: {ports}"},
    "profile.custom.desc": {
        "en": "Using the port list typed in the toolbar",
        "es": "Usa la lista de puertos escrita en la barra",
    },
    # -- report ---------------------------------------------------------
    "report.subtitle": {
        "en": "Network inventory report",
        "es": "Informe de inventario de red",
    },
    "report.range": {"en": "Scope", "es": "Alcance"},
    "report.vpn": {"en": "VPN posture", "es": "Estado VPN"},
    "report.inventory": {"en": "Device inventory", "es": "Inventario de equipos"},
    "report.changes": {
        "en": "Inventory changes since the last review",
        "es": "Cambios de inventario desde la ultima revision",
    },
    "report.pdf": {"en": "Export PDF report", "es": "Exportar informe PDF"},
    "report.html": {"en": "Export HTML report", "es": "Exportar informe HTML"},
    "report.saved": {"en": "Report written to {path}", "es": "Informe guardado en {path}"},
    # -- context menu ----------------------------------------------------
    "ctx.ping": {"en": "Ping (4 packets)", "es": "Ping (4 paquetes)"},
    "ctx.rdp": {"en": "Remote Desktop", "es": "Escritorio remoto"},
    "ctx.web": {"en": "Open in browser", "es": "Abrir en el navegador"},
    "ctx.wol": {"en": "Wake-on-LAN", "es": "Wake-on-LAN"},
    "ctx.copy": {"en": "Copy IP", "es": "Copiar IP"},
    "ctx.audit": {"en": "Audit this device", "es": "Auditar este equipo"},
    "ctx.latency": {
        "en": "Track latency live",
        "es": "Seguir la latencia en vivo",
    },
    "hint.host": {"en": "Enter a host to probe", "es": "Introduce un host para sondear"},
    "ctx.ping_sent": {
        "en": "Ping sent to {ip} (see the console)",
        "es": "Ping enviado a {ip} (mira la consola)",
    },
}
#: Device classification translations, keyed by the canonical English label.
DEVICE_TYPE_KEYS: dict[str, str] = {
    "Router": "type.router",
    "Windows PC": "type.windows",
    "Linux Server": "type.linux",
    "Printer": "type.printer",
    "IoT Device": "type.iot",
    "Apple Device": "type.apple",
    "Raspberry Pi": "type.raspberry",
    "IP Camera": "type.camera",
    "Server": "type.server",
    "Network Device": "type.netdev",
    "Mobile / Tablet": "type.mobile",
    "Mac / Apple": "type.apple",
}

#: Short severity labels used in the findings table.
SEVERITY_KEYS: dict[str, str] = {
    "critical": "sev.critical",
    "high": "sev.high",
    "medium": "sev.medium",
    "low": "sev.low",
    "info": "sev.info",
}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _settings_path() -> Path:
    """Where the language preference is stored between sessions."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return Path(base) / "IPInspector" / "settings.json"


def _detect_system_language() -> Language:
    """Guess the language from the OS locale, defaulting to English."""
    raw = os.environ.get("LANG") or os.environ.get("LC_ALL") or os.environ.get("LANGUAGE") or ""
    lowered = raw.lower()
    if lowered.startswith("es"):
        return "es"
    return DEFAULT_LANGUAGE


def load_preference() -> Language:
    """Read the saved preference, falling back to the system locale."""
    path = _settings_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        saved = data.get("language")
        if saved in LANGUAGES:
            return saved  # type: ignore[return-value]
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return _detect_system_language()


def save_preference(language: Language) -> None:
    """Persist the chosen language, ignoring filesystem failures."""
    path = _settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"language": language}), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Lookup API
# ---------------------------------------------------------------------------

def set_language(language: Language) -> None:
    """Activate a language and persist the choice."""
    global _current
    if language in LANGUAGES:
        _current = language
        save_preference(_current)


def get_language() -> Language:
    """Return the active language code."""
    return _current


def toggle_language() -> Language:
    """Flip between English and Spanish and return the new language."""
    set_language("es" if _current == "en" else "en")
    return _current


def t(key: str, **kwargs: object) -> str:
    """
    Translate a catalogue key into the active language.

    Falls back to English and then to the key itself, so a missing entry
    degrades gracefully instead of raising.
    """
    entry = CATALOG.get(key)
    if entry is None:
        return key
    text = entry.get(_current) or entry.get(DEFAULT_LANGUAGE) or key
    return text.format(**kwargs) if kwargs else text


def device_type_label(device_type: str) -> str:
    """Localised device classification, falling back to the raw value."""
    key = DEVICE_TYPE_KEYS.get(device_type)
    if key:
        return t(key)
    if device_type in ("Unknown", "Desconocido", ""):
        return t("value.unknown")
    return device_type


def severity_label(severity: str) -> str:
    """Localised short severity badge."""
    key = SEVERITY_KEYS.get(severity)
    return t(key) if key else severity.upper()


# ---------------------------------------------------------------------------
# Free-form text translation
# ---------------------------------------------------------------------------

#: Exact whole-line translations for tool and audit output.
LINE_CATALOG: dict[str, dict[str, str]] = {
    "Red": {"en": "Network", "es": "Red"},
    "Mascara": {"en": "Mask", "es": "Mascara"},
    "Primer host": {"en": "First host", "es": "Primer host"},
    "Ultimo host": {"en": "Last host", "es": "Ultimo host"},
    "Broadcast": {"en": "Broadcast", "es": "Broadcast"},
    "Direcciones": {"en": "Addresses", "es": "Direcciones"},
    "Usables": {"en": "Usable", "es": "Usables"},
    "Tipo": {"en": "Type", "es": "Tipo"},
    "Clase": {"en": "Class", "es": "Clase"},
    "privada": {"en": "private", "es": "privada"},
    "publica": {"en": "public", "es": "publica"},
    "Yes": {"en": "Yes", "es": "Si"},
    "No": {"en": "No", "es": "No"},
}

#: Verbatim sentences produced by the tools module.
PHRASE_CATALOG: dict[str, dict[str, str]] = {
    "Transferencia rechazada (configuracion correcta)": {
        "en": "Transfer refused (correct configuration)",
        "es": "Transferencia rechazada (configuracion correcta)",
    },
    "Sin registros": {"en": "No records", "es": "Sin registros"},
    "Dominio vacio": {"en": "Empty domain", "es": "Dominio vacio"},
    "Consulta vacia": {"en": "Empty query", "es": "Consulta vacia"},
    "Destino vacio": {"en": "Empty destination", "es": "Destino vacio"},
    "Host inaccesible o bloquea ICMP": {
        "en": "No reply (unreachable host or ICMP blocked)",
        "es": "Sin respuesta (host inaccesible o bloquea ICMP)",
    },
    "TLS no disponible": {"en": "TLS not available", "es": "TLS no disponible"},
    "TLS not available": {"en": "TLS not available", "es": "TLS no disponible"},
    "Endpoint accesible": {"en": "Endpoint reachable", "es": "Endpoint accesible"},
    "Endpoint reachable": {"en": "Endpoint reachable", "es": "Endpoint accesible"},
}

#: Leading label of a ``Label : value`` pair, matched greedily on the colon.
_LABEL_LINE = re.compile(r"^(\s*)([A-Za-z][A-Za-z ./_-]{1,28}?)\s*(:\s*)(.*)$")

#: ``Label  value`` pairs without a colon (the subnet calculator style).
_LABEL_PAIR = re.compile(r"^(\s*)([A-Za-z][A-Za-z ]{2,18}?)\s{2,}(\S.*)$")

#: Dynamic fragments that need number interpolation.
_PATTERNS: tuple[tuple[re.Pattern[str], dict[str, str]], ...] = (
    (
        re.compile(r"^Puerto (\d+) abierto$"),
        {"en": "Port {0} open", "es": "Puerto {0} abierto"},
    ),
    (
        re.compile(r"^(\d+) findings$"),
        {"en": "{0} findings", "es": "{0} hallazgos"},
    ),
    (
        re.compile(r"^(\d+) dispositivos$"),
        {"en": "{0} devices", "es": "{0} equipos"},
    ),
    (
        re.compile(r"^(\d+) equipos$"),
        {"en": "{0} devices", "es": "{0} equipos"},
    ),
    (
        re.compile(r"^(\d+) shown   ·   sorted by (\w+) (▲|▼)$"),
        {"en": "{0} shown   ·   sorted by {1} {2}", "es": "{0} mostrados   ·   orden por {1} {2}"},
    ),
)


def translate_line(text: str) -> str:
    """
    Translate one line of generated output.

    Handles, in order: exact phrase matches, dynamic numeric patterns, and
    ``Label : value`` / ``Label  value`` pairs. Anything unrecognised is
    returned unchanged, which keeps identifiers and hostnames intact.
    """
    if _current == DEFAULT_LANGUAGE and not text.strip():
        return text

    stripped = text.strip()
    if not stripped:
        return text

    phrase = PHRASE_CATALOG.get(stripped)
    if phrase:
        return phrase.get(_current, phrase[DEFAULT_LANGUAGE])

    # Bare catalogued values such as "privada" on their own line.
    bare = LINE_CATALOG.get(stripped)
    if bare:
        return f"{text[:len(text) - len(text.lstrip())]}{bare[_current]}"

    indent = text[: len(text) - len(text.lstrip())]
    for pattern, variants in _PATTERNS:
        match = pattern.match(stripped)
        if match:
            template = variants.get(_current) or variants[DEFAULT_LANGUAGE]
            return indent + template.format(*match.groups())

    label_match = _LABEL_LINE.match(text) or _LABEL_PAIR.match(text)
    if label_match:
        indent, label, separator, value = (
            label_match.group(1), label_match.group(2),
            label_match.group(3), label_match.group(4),
        )
        translated = LINE_CATALOG.get(label.strip())
        if translated:
            # Keep the original column width so the block stays aligned.
            width = len(label)
            label_text = translated[_current].ljust(width)
            return f"{indent}{label_text}{separator}{value}"

    return text


def translate_lines(lines: list[str]) -> list[str]:
    """Apply :func:`translate_line` across a block of output."""
    return [translate_line(line) for line in lines]


def initialize() -> Language:
    """Load the saved preference at start-up and return the active language."""
    global _current
    _current = load_preference()
    return _current