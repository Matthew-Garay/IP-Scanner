# IP Inspector

Aplicacion de escritorio para Windows que escanea la red local: encuentra los dispositivos conectados, revisa que puertos tienen abiertos, identifica modelo y sistema operativo de cada uno y checa si su configuracion es segura.

Funciona sin conexion una vez instalado y no manda nada a ningun lado. Lo hice para ver que hay en mi propia red sin montar un servidor ni instalar Kali.

- Python 3.13 o superior
- Interfaz con CustomTkinter

---

## Que trae

La app tiene seis pestanas en una sola ventana. *Network Scan* es lo principal: descubre los equipos y sondea los puertos TCP del 1 al 1024 (siempre los mismos, para que dos escaneos se puedan comparar). Tambien toma las IPs de la VPN del equipo, no solo la tarjeta fisica.

*Security Audit* revisa TLS y HTTP de cada equipo y le da una puntuacion de riesgo. *Tools* y *Quick Tools* son utilidades sueltas: DNS, WHOIS, traceroute, calculo de subredes, grafica de latencia. *Inventory* guarda lo visto y lo compara con una linea base para notar si algo aparecio o se fue, y *Monitor* revisa cada pocos minutos si los equipos siguen respondiendo.

La interfaz esta en ingles y espanol, se cambia en caliente, y los informes PDF y HTML salen en el idioma activo.

---

## Instalacion

```powershell
git clone https://github.com/Matthew-Garay/IP-Scanner.git
cd IP-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r ip_inspector\requirements.txt
```

Las dependencias son `customtkinter`, `scapy`, `psutil` y `mac-vendor-lookup`. Esta ultima descarga la lista de fabricantes de MAC en el primer arranque y despues trabaja sin conexion. `netifaces` no esta porque no publica paquetes para Python 3.13 y con `psutil` basta.

---

## Uso

```powershell
python -m ip_inspector.main
```

Hay que **correrlo como administrador**. Sin ese permiso Windows no deja abrir los sockets del sondeo de descubrimiento y la app no ve los equipos que contestan por ARP.

Pruebas:

```powershell
python -m unittest discover -s tests -t . -v
```

Cada prueba existe porque ese bug ya salio antes y no quiero que vuelva.

---

## Compilar el ejecutable

```powershell
pip install pyinstaller
pyinstaller ip_inspector\IP_Inspector.spec
```

El `.spec` apunta a `ip_inspector/launcher.py` y no a `main.py` a proposito: PyInstaller no sigue la importacion relativa (`from .interface.ui import ...`), empaqueta `main.py` solo y el ejecutable arranca vacio. Con `launcher.py` la importacion es absoluta y el analizador ve todo el paquete. Sale como `dist/IP_Inspector.exe`.

---

## Estructura

El codigo va en capas y cada una solo importa de las de abajo:

```
core       el motor: modelos, utilidades, sondeo, el escaner
analysis   que significan los hallazgos: riesgo, exposicion, informes
actions    que se le puede hacer a un equipo: abrirlo, despertarlo, exportarlo
nettools   las pestanas de herramientas y el monitor
interface  todo lo que toca tkinter
i18n       el catalogo bilingue
```

Como `core` no importa la interfaz, se puede usar sin pantalla (por eso un escaneo se puede programar en una maquina sin monitor). La interfaz no se importa desde `__init__.py` para que usar solo el motor no cargue tkinter.

Lo largo corre en un hilo trabajador que deja resultados en una `queue.Queue`, y el hilo principal los saca con `after()`. Es la forma segura de tocar tkinter desde otro hilo y la ventana no se congela.

---

## Uso responsable

Esto sondea equipos ajenos. Usalo solo en redes donde tengas permiso.