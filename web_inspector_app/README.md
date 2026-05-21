# Vulneraweb Analytics

Aplicacion web hecha con Python, HTML, CSS y JavaScript para inspeccionar vulnerabilidades de un sitio web o IP:

- Resolucion de host e IPs
- Respuesta HTTP y cabeceras relevantes
- Conteo de formularios, scripts y enlaces
- Lectura basica de TLS en sitios HTTPS
- Integracion con `nmap` para obtener estados de puertos si la herramienta esta instalada
- Historial de escaneos persistido en `data/scan_history.json`
- Validacion basica de IP, URL o dominio antes de ejecutar la inspeccion

## Estructura

```text
web_inspector_app/
├── app.py
├── requirements.txt
├── services/
│   ├── nmap_service.py
│   └── web_analyzer.py
├── static/
│   ├── css/styles.css
│   └── js/app.js
└── templates/
    └── index.html
```

## Puesta en marcha

1. Instala Python 3.
2. Crea y activa un entorno virtual.
3. Instala dependencias.
4. Ejecuta Flask.

Ejemplo en Windows:


```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
La aplicacion quedara disponible en `http://127.0.0.1:5000`.

## Nmap

La app intenta ejecutar este comando cuando el objetivo es un dominio:

```text
nmap -Pn -T3 --top-ports 20 <host> -oX -
```

Cuando el objetivo es una IP, usa un perfil con deteccion de version de servicio:

```text
nmap -Pn -T3 -sV --top-ports 50 <ip> -oX -
```

Si `nmap` no esta instalado o no esta en `PATH`, la aplicacion seguira funcionando y mostrara un aviso.

Si quieres usar otro ejecutable o una envoltura como WSL/Kali, puedes definir la variable de entorno `NMAP_COMMAND`.

Ejemplos:

```powershell
$env:NMAP_COMMAND = "nmap"
python app.py
```

```powershell
$env:NMAP_COMMAND = "wsl nmap"
python app.py
```

## Nota importante

Usa esta herramienta solo con autorizacion expresa sobre infraestructuras propias o entornos de laboratorio.
