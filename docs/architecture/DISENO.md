# Diseño de la aplicación

Esta guía describe cómo se organizó el proyecto y qué cambios se aplicaron
para ordenarlo.

## Estructura actual

```
ip_inspector/
  core/            El motor: modelos, utilidades, sondeo, NetworkScanner
  analysis/        Lo que significan los hallazgos: riesgo, exposición, informes
  actions/         Lo que se puede hacer con un equipo
  nettools/        Pestañas de herramientas y el monitor
  interface/       Todo lo que toca tkinter (UI y reparto de estilos)
  i18n.py          Catálogo bilingüe
launcher.py        Punto de entrada para PyInstaller
main.py            Punto de entrada de desarrollo
tests/             Regresiones fijadas con tests
```

## Regla de oro de capas

Cada capa solo puede importar de las que están por debajo:

1. `core` (modelos + motor) → depende solo de estándar de biblioteca y de `ping`.
2. `analysis` → depende de `core`.
3. `actions` → depende de `core`.
4. `nettools` → depende de `core` y `analysis`.
5. `interface` → todo lo demás, y solo aquí toca tkinter.
6. `i18n` → no importa a ninguna capa de aplicación; se usa por toda la pila.

## Cambios en la organización

### 1. Construcción del dominio (`core/models.py`)

- Se extrajo la configuración del dominio (anchos de ventana, colores de estado
  y constantes de escaneo) de la interfaz a `core/models.py`, donde es
  independiente de la biblioteca gráfica y compartible por todos los módulos.
  - `MIN_WINDOW_WIDTH = 1400` → ancho cuando la ventana no puede encogerse.
  - `TABLE_MIN_HEIGHT = 420` → altura mínima de la tabla de resultados.
- `ports_compact()` ahora devuelve **todos** los puertos abiertos como texto
  plano, sin `fit` ni truncado. El método `ports_summary()` conserva la lista
  completa y es la que alimenta contexto, exportación e informe.

### 2. Representación (interfaz)

- `interface/ui.py` usa `WINDOW_MINIMUM = (1400, 760)`, que coincide con
  `MIN_WINDOW_WIDTH` del dominio.
- `interface/theme.py` redefine `ResultTable`:
  - `grid_propagate(False)` para que la tabla no se redimensione por su
    contenido; su tamaño se calcula desde la cuadrícula.
  - `body` ya no es `ctk.CTkScrollableFrame`; es un `ctk.CTkFrame` que crece
    verticalmente. No hay scroll ni scrollbard, y las filas mantienen su altura
    fija (`ROW_HEIGHT = 26`).
  - `_sync_gutter()` es una no-op porque ya no hay scrollbar.

### 3. Consistencia de tamaños

- `MIN_WINDOW_WIDTH` (dominio): 1400.
- `WINDOW_MINIMUM` (UI): (1400, 760).
- `TABLE_MIN_HEIGHT` (dominio): 420.
- La suma de los anchos declarados en `DEVICE_COLUMNS` es 1208 px.
  El `body` se expande proporcionalmente, con `minsize` y `weight` en cada
  columna, por lo que no se aplana ni se pierden los encabezados.

### 4. Tests

Se dejaron intactos los tests existentes porque los recrean. Se ejecutaron con
`python -m unittest discover -s tests -t . -v` (40 pruebas, 8 saltadas por
falta de tkinter; sin tkinter las pruebas de interfaz se omiten).

## Convenciones de codificación

- Datos puros y sin dependencias externas en `core/models.py` para que el
  motor no importe tkinter ni scapy ahí.
- Uso de `from __future__ import annotations`; `slots=True` en dataclasses.
- Archivos fuente en UTF-8.
- `customtkinter` es la única librería GUI.
- Los records de prueba solo usan la librería estándar.
