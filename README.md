# IP Inspector

Aplicacion de escritorio para Windows que descubre los dispositivos de una red
local, analiza que puertos tienen abiertos, identifica el modelo y el sistema
operativo de cada equipo y audita su postura de seguridad.

Todo ocurre en la red local del operador: no sale a Internet, no sube datos a
ningun servicio y funciona sin conexion una vez instalado.

- **Autor:** Matthew Garay
- **Lenguaje:** Python 3.13+
- **Interfaz:** CustomTkinter (escritorio nativo de Windows)

---

## Que hace

La aplicacion tiene seis pestanas que comparten una sola ventana:

| Pestana | Funcion |
| --- | --- |
| **Network Scan** | Descubrimiento de hosts y sondeo de puertos TCP. |
| **Security Audit** | TLS, postura HTTP y puntuacion de riesgo por dispositivo. |
| **Tools** | DNS, WHOIS, traceroute, calculo de subredes y exposicion local. |
| **Quick Tools** | Traceroute visual, grafico de latencia en vivo, subredes y DNS. |
| **Inventory** | Dispositivos vistos hasta ahora, comparados contra una linea base. |
| **Monitor** | Comprobaciones continuas de disponibilidad y avisos. |

Detalles de comportamiento que conviene conocer antes de usarla:

- El barrido es fijo: recorre los puertos **1 a 1024**. El operador ya no elige
  la lista de puertos, de modo que cada barrido hace siempre la misma pregunta
  (cuales de esos son alcanzables) y los resultados de dos escaneos son
  comparables. Los puertos por encima de 1024 quedan para el diagnostico
  propio de la pestana Tools.
- El escaneo tambien recorre las IPs asignadas a la VPN del equipo, no solo la
  LAN fisica.
- La interfaz es **bilingue** (ingles / espanol). El idioma cambia en caliente y
  los informes PDF y HTML se generan en el idioma activo.

---

## Instalacion

Requiere Python 3.13 o superior.

```powershell
git clone https://github.com/Matthew-Garay/IP-Scanner.git
cd IP-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r ip_inspector\requirements.txt
```

Dependencias (`ip_inspector/requirements.txt`):

| Paquete | Para que se usa |
| --- | --- |
| `customtkinter` | Widgets de la interfaz de escritorio. |
| `scapy` | Sondeo de la capa 2 (descubrimiento de hosts en el segmento). |
| `psutil` | Detalle de las interfaces de red del equipo. |
| `mac-vendor-lookup` | Lista de fabricantes IEEE OUI; se descarga y cachea en el primer uso, despues funciona sin conexion. |

`netifaces` se deja fuera a proposito: no publica ruedas para Python 3.13+ y
obligaria a instalar un compilador de Visual C++. `psutil` ya expone todos los
datos de interfaz que necesita el escaner.

---

## Uso

Desde la raiz del repositorio:

```powershell
python -m ip_inspector.main
```

Tambien funciona como script suelto:

```powershell
python ip_inspector\main.py
```

Para empezar a escanear hay que **ejecutar el programa como administrador**.
Sin ese permiso Windows no permite abrir los sockets sin privilege para las
direcciones de difusion, y el escaner no ve los hosts que responden por ARP.

---

## Pruebas

Las pruebas solo usan la libreria estandar. Cada una reproduce un fallo real que
estuvo en produccion: son las trampas concretas en las que ha caido la
aplicacion, fijadas para que no vuelvan a caerse sin que nadie se entere.

```powershell
python -m unittest discover -s tests -t . -v
```

---

## Empaquetado en un ejecutable

```powershell
pip install pyinstaller
pyinstaller ip_inspector\IP_Inspector.spec
```

El `.spec` empaqueta `ip_inspector/launcher.py`, que es el punto de entrada que
PyInspector resuelve bien. `main.py` usa una importacion relativa
(`from .interface.ui import ...`) que el analizador de PyInstaller solo resuelve
a medias: empaqueta `main.py` pero se deja los subpaquetes hermanos fuera, y el
ejecutable arranca sin ninguna de las capas. `launcher.py` importa el punto de
entrada de forma absoluta (`from ip_inspector.main import main`), lo que hace
visible todo el paquete al analizador.

El ejecutable resultante es `dist/IP_Inspector.exe`.

---

## Estructura del codigo

El paquete es una pila de capas y cada una solo puede importar de las que tiene
debajo:

```
core       motor: modelos, utilidades, sondeo y el propio escaner
analysis   que significan los hallazgos: riesgo, exposicion, informes
actions    que se puede hacer con un dispositivo: abrirlo, despertarlo, exportarlo
nettools   las pestanas Tools y el monitorizacion continua
interface  todo lo que toca tkinter
i18n       el catalogo bilingue, usado por los informes y la ventana
```

Esta disciplina no es estetica. El motor (`core`) no importa la interfaz, asi
que se puede usar sin pantalla: por eso un escaneo puede programarse en una
maquina sin monitor. Y `models.py` no depende de nada, de modo que la
interfaz se puede razonar y comprobar sin abrir un socket.

Superficie publica del paquete:

```python
from ip_inspector import NetworkScanner, ScanRequest, Device
from ip_inspector import tools, audit
```

La interfaz no se importa desde `__init__.py` a proposito, para que un consumo
sin pantalla del motor no cargue tkinter.

---

## Modelo de hilos

Toda operacion larga corre en un hilo trabajador que deposita los resultados en
una `queue.Queue`. El hilo principal la vacia con `after()`, que es la unica
forma segura de actualizar tkinter desde otro hilo y mantiene la ventana
responsiva durante un barrido completo.

---

## Uso responsable

Esta herramienta enumera y sondea otros equipos. Solo escanea redes sobre las
que tenga autorizacion expresa. Sondear una red que no es suya puede ser ilegal
y, con independencia de la ley, siempre es una forma de evitar el trabajo de
pedir permiso.

---

## Estructura de commits

Los mensajes estan en castellano y describen el efecto del cambio, no el
movimiento de archivos:

```
Rediseña la interfaz al estilo de un escaner de red profesional
Arregla las columnas, el escaneo con VPN y la identificacion de camaras
fix: agregar slash final a URL de wasm en pdfjs.js para evitar error Invalid factory url
```
