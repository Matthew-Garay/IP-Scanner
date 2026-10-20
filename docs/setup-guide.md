# Guia de Instalacion - IP Scanner

Esta guia te ayuda a instalar y ejecutar IP Scanner en tu entorno local.

## Requisitos previos

- Windows 10 o Windows 11
- Python 3.13 o superior
- Permisos de administrador (para sondeo de descubrimiento de red)

## Instalacion

1. Clona el repositorio:
   ```bash
   git clone https://github.com/Matthew-Garay/IP-Scanner.git
   cd IP-Scanner
   ```

2. Crea y activa un entorno virtual:
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

4. Ejecuta la aplicación como administrador:
   ```bash
   python -m ip_inspector.main
   ```

## Verificacion

La aplicación debe abrir una ventana mostrando la interfaz de escaneo de red con la tabla de dispositivos y las pestañas de herramientas.

## Ejecutar pruebas

```bash
python -m pytest tests/ -v
```

## Compilar ejecutable

```bash
pip install pyinstaller
pyinstaller IP_Inspector.spec
# Resultado: dist\IP_Inspector.exe
```

## Uso responsable

Esta herramienta sondea equipos de red. Usala solo en redes donde tengas permiso.
