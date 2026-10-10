# IP Inspector

Aplicación de escritorio para Windows que escanea la red local: descubre
dispositivos conectados, revisa puertos abiertos, identifica modelo y sistema
operativo, y evalúa la postura de seguridad de cada host. Interfaz estilo
Advanced IP Scanner: tabla virtualizada de 6 columnas (Estado, IP, Nombre,
MAC, Fabricante, Puertos), con scroll nativo y modos Rápido/Completo.

Dependencias producción: `customtkinter`, `scapy`, `psutil`, `mac-vendor-lookup`.

## Estructura ordenada

```
D:/Escaner de puertos/
  IP_Inspector.spec      spec con rutas relativas (pyinstaller IP_Inspector.spec)
  requirements.txt       dependencias (raiz, no dentro del paquete)
  README.md / AGENTS.md / ARCHITECTURE.md
  ip_inspector/          paquete (sin .venv ni dist dentro)
    core/                modelos, utils, sondeo, NetworkScanner
    analysis/            riesgo, exposicion, informes
    actions/             abrir, WoL, exportar
    nettools/            tools, monitor, profiles
    interface/           ui.py + theme.py + fasttable.py (tabla virtualizada)
    i18n.py              catalogo bilingue
    launcher.py / main.py / assets/
  tests/                 regresiones (solo stdlib)
  docs/architecture/     nota de diseno
```

`.venv/` vive en `ip_inspector/.venv` (heredado); lo ideal es recrearlo en la
raiz con `python -m venv .venv`. `dist/` con el .exe tambien debe salir del
paquete a la raiz (PyInstaller lo genera ahi con el spec nuevo).

## Regla de oro de capas

El paquete es una pila donde cada capa solo puede importar de las que está
por debajo:

```
core       -> modelos, utilidades, sondeo, NetworkScanner
analysis   -> ide de core (auditoría, exposición, informes)
actions    -> lo que puede hacerse con un equipo (abrir, WoL, exportar)
nettools   -> pestañas de herramientas y monitor
i18n       -> catálogo bilingüe, usado por los informes y la ventana
interface  -> todo lo que toca tkinter
```

`core` nunca importa a `interface`; por eso el motor puede funcionar sin
pantalla. La interfaz nunca se importa desde `__init__.py` de la raíz.

## Dónde buscar

| Capa | Pila | Responsabilidades |
| ---- | ---- | ----------------- |
| **core** | `core/models.py`, `core/utils.py`, `core/network.py`, `core/ping.py`, `core/identify.py`, `core/hostnames.py` | Modelos de dominio (Device, Port, ScanRequest…), auxiliares de la plataforma, motor de escaneo y detección. |
| **analysis** | `analysis/audit.py`, `analysis/exposure.py`, `analysis/report.py` | Qué significan los hallazgos: puntuación de riesgo, análisis de exposición y generación de PDF/HTML. |
| **actions** | `actions/exporter.py`, `actions/menu.py`, `actions/wol.py` | Acciones sobre un dispositivo: exportar, abrir RDP/web, WoL, menú contextual. |
| **nettools** | `nettools/tools.py`, `nettools/monitor.py`, `nettools/profiles.py` | Pestañas Tools y Quick Tools, y el monitor continuo. |
| **interface** | `interface/ui.py`, `interface/theme.py`, `interface/i18n.py` | Todo lo que toca tkinter y la interfaz de usuario. |
| **i18n** | `i18n.py` | Catálogo bilingüe; aplicarlo a la salida humana, no a las claves de datos. |

Agregue un módulo en `core` o `analysis` respetando esta pila. Si necesita
escribir en la ventana, hágalo en `interface`, no en el motor.

## Convenciones

- **Python 3.13+**, tipado explícito (`from __future__ import annotations`).
- Datos puros y libres de dependencias en `core/models.py`; el motor no puede
  importar tkinter ni scapy desde ahí.
- Todos los módulos de la capa `core` y `analysis` declaran ante
  `from __future__ import annotations` y los dataclass con `slots=True`.
- Los reportes PDF/HTML y la tabla composición se traen de `core.models` o
  de módulos analíticos, nunca se generan en `interface`.
- Los textiles de todos los archivos fuente son UTF-8 (el código usa
  `encoding="utf-8"` explícito en `open()` y `write_text`).
- `customtkinter` es la única librería GUI; no añadir dependencias third-party.

## Pruebas

```powershell
python -m unittest discover -s tests -t . -v
```

Solo usa la librería estándar. Cada prueba es una trampas documentó un fallo
real que tuvo la aplicación; mantenlas actualizadas si se cambia ese contrato.

## Comandos

- Ejecutar: `python -m ip_inspector.main` (requiere administrador Windows).
- Empaquetar: `pyinstaller ip_inspector\IP_Inspector.spec` → `dist/IP_Inspector.exe`.
- El `.spec` apunta a `launcher.py` (no a `main.py`) porque PyInstaller no
  resuelve las importaciones relativas; `launcher.py` arranca el paquete desde
  `ip_inspector.main`.

## Notas de diseño (cambios recientes)

- Tabla `ResultTable` sobresale de `ResultTable.{ROW_HEIGHT, HEADER_FONT_SIZE,
  ROW_FONT_SIZE, ROW_FONT_PADDING}`; no añada columnas por fuera de
  `DEVICE_COLUMNS` sin actualizar `ui.py` y los tests de geometría.
- `ports_compact()` devuelve todos los puertos abiertos como texto plano,
  sin truncado; la información completa queda en `ports_summary`, en el
  menú contextual, en la exportación y en el informe.
- La ventana mínima es `(1400, 760)`; `MIN_WINDOW_WIDTH` y `TABLE_MIN_HEIGHT`
  viven en `core/models.py` (el dominio), `WINDOW_MINIMUM` en `interface/ui.py`
  (la representación).
- La tabla de resultados no vuelve a `ctk.CTkScrollableFrame`; el propio
  `ResultTable` es el contenedor y el `body` es un `ctk.CTkFrame` que crece
  verticalmente. Ya no hay scroll horizontal ni vertical.
