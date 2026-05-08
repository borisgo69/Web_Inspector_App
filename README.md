# Web Inspector

Aplicacion web hecha con Python, HTML, CSS y JavaScript para inspeccionar un sitio a nivel basico:

- Resolucion de host e IPs
- Respuesta HTTP y cabeceras relevantes
- Conteo de formularios, scripts y enlaces
- Lectura basica de TLS en sitios HTTPS
- Integracion con `nmap` para obtener puertos abiertos si la herramienta esta instalada

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

La app intenta ejecutar este comando:

```text
nmap -Pn -T3 --top-ports 20 --open <host> -oX -
```

Si `nmap` no esta instalado o no esta en `PATH`, la aplicacion seguira funcionando y mostrara un aviso.
