<div align="center">

# 🔍 IP Inspector — Escáner de Red y Puertos

**Aplicación de escritorio para Windows** que escanea la red local, detecta dispositivos, revisa puertos y audita su seguridad.

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CustomTkinter](https://img.shields.io/badge/CustomTkinter-GUI-2ea44f?style=flat-square)](https://customtkinter.tomschimansky.com/)
[![Windows](https://img.shields.io/badge/Plataforma-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)]()
[![Idiomas](https://img.shields.io/badge/Idiomas-ES%20%7C%20EN-6f42c1?style=flat-square)]()

</div>

---

## 📖 Descripción

Aplicación de escritorio para Windows que escanea la red local: encuentra los dispositivos conectados, revisa qué **puertos TCP** tienen abiertos, identifica **modelo y sistema operativo** de cada equipo y comprueba si su configuración es segura.

Funciona **sin conexión** una vez instalado y **no envía datos a ningún lado**. Está pensada para saber qué hay en tu propia red sin montar un servidor ni instalar Kali.

## ✨ Características

- **Network Scan (principal):** descubre equipos y sondea los puertos TCP del 1 al 1024 (siempre los mismos, para poder comparar escaneos). Detecta también IPs de la VPN, no solo la tarjeta física.
- **Security Audit:** revisa TLS y HTTP de cada equipo y asigna una puntuación de riesgo.
- **Tools y Quick Tools:** DNS, WHOIS, traceroute, cálculo de subredes y gráfica de latencia.
- **Inventory:** guarda lo visto y lo compara con una línea base para detectar equipos que aparecen o desaparecen.
- **Monitor:** revisa periódicamente si los equipos siguen respondiendo.
- **Interfaz bilingüe** (español/inglés) con cambio en caliente; informes PDF y HTML en el idioma activo.

## 🛠️ Tecnologías utilizadas

- **Lenguaje:** Python 3.13+
- **GUI:** CustomTkinter
- **Red:** scapy, psutil, mac-vendor-lookup (lista OUI de fabricantes, se descarga y cachea en el primer uso)
- **Empaquetado:** PyInstaller (`IP_Inspector.spec`)

## 📋 Requisitos previos

- **Windows** (la app está diseñada para escritorio Windows).
- **Python 3.13 o superior.**
- Permisos de **administrador** para el sondeo de descubrimiento (sockets/ARP).

## 🚀 Instalación

```powershell
git clone https://github.com/Matthew-Garay/IP-Scanner.git
cd IP-Scanner
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r ip_inspector\requirements.txt
```

Dependencias: `customtkinter`, `scapy`, `psutil` y `mac-vendor-lookup`. `netifaces` se omite a propósito (no publica paquetes para Python 3.13).

## 🧪 Uso

Ejecuta la aplicación **como administrador** (sin ese permiso Windows bloquea los sockets del sondeo):

```powershell
python -m ip_inspector.main
```

**Pruebas:**

```powershell
python -m unittest discover -s tests -t . -v
```

**Compilar el ejecutable:**

```powershell
pip install pyinstaller
pyinstaller ip_inspector\IP_Inspector.spec
# Resultado: dist\IP_Inspector.exe
```

## 📂 Estructura del proyecto

El código va en **capas** y cada una solo importa de las de abajo:

```
ip_inspector/
├── core/        # Motor: modelos, utilidades, sondeo, escáner
├── analysis/    # Interpretación de hallazgos: riesgo, exposición, informes
├── actions/     # Acciones sobre un equipo: abrirlo, despertarlo, exportarlo
├── nettools/    # Pestañas de herramientas y monitor
├── interface/   # Todo lo que toca tkinter
├── i18n.py      # Catálogo bilingüe
├── launcher.py  # Punto de entrada para PyInstaller
└── main.py      # Punto de entrada en desarrollo
```

Como `core` no importa la interfaz, el motor puede usarse sin pantalla. El trabajo largo corre en un **hilo trabajador** que entrega resultados por `queue.Queue`, y el hilo principal los consume con `after()` para no congelar la ventana.

## ⚠️ Uso responsable

Esto sondea equipos ajenos. **Úsalo solo en redes donde tengas permiso.**

## 📜 Licencia

Proyecto educativo y de código abierto; puedes usarlo libremente con fines de aprendizaje y redes propias.

## ✍️ Autor

**Matthew Garay** — [GitHub](https://github.com/Matthew-Garay)
