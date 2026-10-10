# Arquitectura de IP Inspector

Esta aplicación es un escáner de red de escritorio para Windows con una
interfaz gráfica hecha con `customtkinter`. El objetivo es que cualquier
tecnólogo pueda ejecutarlo sin conexión y sin enviar datos a ningún servidor.

## Capas

```
core
  Modelos de dominio y motor de escaneo.
  Importa solo estándar de biblioteca (y `ping` para TTL).
analysis
  Interpretación de los datos: puntuación de riesgo, exposición, reportes.
actions
  Acciones concretas sobre un dispositivo: exportar, abrir RDP, Wake-on-LAN.
nettools
  Pestañas de herramientas y monitor continuo.
interface
  Todo lo que toca tkinter y la apariencia.
i18n
  Catálogo bilingüe (inglés/español) aplicado a la salida humana.
```

La regla es que ninguna capa de arriba puede importar una capa de abajo,
excepto `interface`. Eso permite que `core` se use sin pantalla (por ejemplo,
en un servicio headless) e impide acoplar lógica de aplicación a tkinter.

## Datos y negocio

- Todo los datos se manipulan en `core/models.py` y `core/network.py`.
  - `Device` es la unidad de trabajo: IP, MAC, hostname, open ports, modelo,
    puntuación de riesgo, hallazgos de exposición.
  - `ScanRequest` describe un escaneo (rango, puertos, tiempo de espera,
    concurrencia, resolución de nombres...), pero no lo ejecuta.
- `core/network.py` es el motor: ARP sweep + sondeo TCP por hilos,
  clasificación de dispositivos y emisión de eventos a los subprocesos.
- `analysis/` tiene las reglas de postura: `audit.py` (TLS, HTTP, puntuación
  de riesgo), `exposure.py` (equipos a la intemperie) y `report.py` (PDF/HTML).

## Interfaz

- `interface/ui.py` es la ventana principal: `IPInspectorApp(ctk.CTk)`.
  Gestiona cinco pestañas, una tabla de resultados con 16 columnas, el
  estado del hilo de escaneo y los herramientas rápidas.
- `interface/theme.py` provee los colores y los widgets reutilizables
  (botones, campos, `ResultTable`, LEDs, `Sparkline`).
- `interface/i18n.py` aplica la traducción tanto a los valores literales
  como a las salidas humanas liberadas desde los paneles analíticos.

## Flujo de escaneo

1. El usuario escribe un rango (o el sistema sugiere una red).
2. `NetworkScanner` realiza un barrido ARP, luego un sondeo TCP concurrente
   (por pares host/puerto, 1024 puertos en `SCAN_PORTS`).
3. Mientras el escaneo corre, el hilo principal sirve los eventos de
   `ScannerEvent` mediante `after()` para no bloquear la ventana.
4. Cuando termina, `score_devices()` aplica las reglas de análisis y la
   tabla se actualiza sin recrearse.

## Pruebas

Solo la librería estándar:

```powershell
python -m unittest discover -s tests -t . -v
```

Cada prueba fija una regresión documentada.

## Despliegue

`launcher.py` es el archivo que PyInstaller empaca; apunta a `ip_inspector.main`,
no a `main.py`, porque el analizador no resuelve las importaciones
relativas. El ejecutable sale en `dist/IP_Inspector.exe`.
