# IP Inspector Escaner de Red y Puertos

## Acerca de

Aplicacion de escritorio para Windows que escanea la red local, detecta dispositivos conectados, revisa puertos TCP abiertos, identifica modelo y sistema operativo de cada equipo y audita su configuracion de seguridad. Proporciona visibilidad sobre los dispositivos presentes en una red local sin necesidad de instalar herramientas complejas ni montar un servidor. Ejecucion local en Windows con Python 3.13, sin envio de datos a servidores externos.

## Caracteristicas principales

- Network Scan: descubrimiento de equipos y sondeo de puertos TCP del 1 al 1024, incluida deteccion de IPs de VPN.
- Security Audit: revision de TLS y HTTP de cada equipo con puntuacion de riesgo.
- Herramientas de red: DNS, WHOIS, traceroute, calculo de subredes y grafica de latencia.
- Inventario: almacenamiento de escaneos previos y comparacion con linea base.
- Monitor: revision periodica de disponibilidad de equipos en la red.
- Interfaz bilingue (espanol/ingles) con cambio en caliente e informes PDF y HTML.

## Stack tecnologico

| Categoria | Tecnologia |
|-----------|------------|
| Lenguaje | Python 3.13+ |
| GUI | CustomTkinter |
| Red | scapy, psutil, mac-vendor-lookup |
| Empaquetado | PyInstaller |
| Sistema operativo | Windows |

## Creditos

Desarrollado por: Matthew Ilveneff Garay Perez
Correo Electronico: 1911.garay.perez@gmail.com