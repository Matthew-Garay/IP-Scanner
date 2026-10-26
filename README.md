# IP Inspector Escaner de Red y Puertos

## A. Titulo del Proyecto y Resumen Ejecutivo

IP Inspector es una aplicacion de escritorio para Windows que escanea la red local, detecta dispositivos conectados, revisa puertos TCP abiertos, identifica modelo y sistema operativo de cada equipo y audita su configuracion de seguridad. El problema que resuelve es proporcionar visibilidad sobre los dispositivos presentes en una red local sin necesidad de instalar herramientas complejas ni montar un servidor. Su alcance tecnologico se limita a la ejecucion local en Windows con Python 3.13, sin envio de datos a servidores externos.

## B. Arquitectura del Sistema

El programa sigue una arquitectura por capas donde cada capa solo importa de las capas inferiores. La capa interface (CustomTkinter) interactua con el usuario y envia solicitudes a la capa de acciones. La capa de acciones coordina con la capa de analisis para interpretar hallazgos de seguridad. La capa de analisis se apoya en la capa de red y escaneo para obtener datos de los dispositivos. La capa de red y escaneo utiliza modelos de dominio definidos en la capa core. El flujo de datos va de la interfaz hacia el motor de escaneo y los resultados regresan por la misma ruta para ser mostrados en pantalla. El trabajo largo se ejecuta en un hilo trabajador que entrega resultados mediante queue.Queue, y el hilo principal los consume para no congelar la ventana.

## C. Caracteristicas Tecnicas Clave

- Network Scan: descubrimiento de equipos y sondeo de puertos TCP del 1 al 1024, incluyendo deteccion de IPs de VPN.
- Security Audit: revision de TLS y HTTP de cada equipo con asignacion de puntuacion de riesgo.
- Herramientas de red: DNS, WHOIS, traceroute, calculo de subredes y grafica de latencia.
- Inventario: almacenamiento de escaneos previos y comparacion con una linea base para detectar apariciones o desapariciones de equipos.
- Monitor: revision periodica de disponibilidad de equipos en la red.
- Interfaz bilingue (espanol/ingles) con cambio en caliente y generacion de informes PDF y HTML.
- Arquitectura por capas con separacion entre motor de escaneo (core) y interfaz de usuario.
- Procesamiento asincrono mediante hilo trabajador y queue.Queue para no bloquear la interfaz.
- No utiliza base de datos persistente ni protocolo de red propio mas alla del escaneo local.
- Seguridad basada en el uso responsable; la herramienta sondea equipos ajenos y debe usarse solo con permiso.

## D. Especificacion del Stack Tecnologico

| Categoria | Tecnologia / Libreria |
|-----------|----------------------|
| Lenguaje | Python 3.13+ |
| GUI | CustomTkinter |
| Red | scapy, psutil, mac-vendor-lookup |
| Empaquetado | PyInstaller |
| Sistema operativo | Windows |

## E. Guia de Instalacion, Configuracion y Despliegue

### Requisitos previos del sistema

- Windows (aplicacion disenada para escritorio Windows).
- Python 3.13 o superior.
- Permisos de administrador para el sondeo de descubrimiento (sockets y ARP).

### Secuencia de comandos para clonacion e instalacion

git clone https://github.com/Matthew-Garay/IP-Scanner.git
cd IP-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

### Configuracion de variables de entorno

Este proyecto no requiere archivo .env ni variables de entorno.

### Comandos para ejecucion en entorno de Desarrollo

python -m ip_inspector.main

### Comandos para ejecucion en entorno de Produccion

No aplica entorno de produccion separado; la aplicacion se ejecuta localmente con el mismo comando de desarrollo.

## F. Creditos de Autoría

Desarrollado por: Matthew Ilveneff Garay Perez
Correo Electronico: 1911.garay.perez@gmail.com
