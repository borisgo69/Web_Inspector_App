import ipaddress
import os
import shlex
import subprocess
import xml.etree.ElementTree as ET


def _is_valid_scan_target(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 253:
        return False

    labels = host.rstrip(".").split(".")
    if not labels:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False

    return True


def _parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    host_node = root.find(".//host")

    if host_node is None:
        return {
            "status": "unknown",
            "open_ports": [],
            "scanned_ports": [],
            "summary": "Nmap no devolvio informacion del host.",
        }

    status_node = host_node.find("status")
    status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"

    open_ports = []
    scanned_ports = []
    for port_node in host_node.findall("./ports/port"):
        state_node = port_node.find("state")
        state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
        reason = state_node.attrib.get("reason", "") if state_node is not None else ""

        service_node = port_node.find("service")
        port_info = {
            "port": int(port_node.attrib.get("portid", 0)),
            "protocol": port_node.attrib.get("protocol", "tcp"),
            "state": state,
            "reason": reason,
            "service": service_node.attrib.get("name", "desconocido") if service_node is not None else "desconocido",
            "product": service_node.attrib.get("product", "") if service_node is not None else "",
            "version": service_node.attrib.get("version", "") if service_node is not None else "",
        }
        scanned_ports.append(port_info)

        if state == "open":
            open_ports.append(port_info)

    if open_ports:
        summary = f"Se han detectado {len(open_ports)} puertos abiertos."
    else:
        summary = "No se han detectado puertos abiertos en el perfil analizado."

    return {"status": status, "open_ports": open_ports, "scanned_ports": scanned_ports, "summary": summary}


def _build_nmap_command(host: str) -> list[str]:
    raw_command = os.environ.get("NMAP_COMMAND", "nmap")
    base_command = shlex.split(raw_command, posix=False)
    return [*base_command, "-Pn", "-T3", "--top-ports", "20", host, "-oX", "-"]


def run_nmap_scan(host: str) -> dict:
    command = _build_nmap_command(host)

    if not _is_valid_scan_target(host):
        return {
            "available": False,
            "executed": False,
            "message": "El host no tiene un formato valido para ejecutar nmap.",
            "open_ports": [],
            "scanned_ports": [],
            "command": " ".join(command),
        }

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except FileNotFoundError:
        return {
            "available": False,
            "executed": False,
            "message": "Nmap no esta instalado o no se encuentra en PATH.",
            "open_ports": [],
            "scanned_ports": [],
            "command": " ".join(command),
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "executed": False,
            "message": "La ejecucion de nmap ha excedido el tiempo limite.",
            "open_ports": [],
            "scanned_ports": [],
            "command": " ".join(command),
        }

    if completed.returncode not in (0, 1):
        stderr = completed.stderr.strip() or "Nmap ha devuelto un error inesperado."
        return {
            "available": True,
            "executed": False,
            "message": stderr,
            "open_ports": [],
            "scanned_ports": [],
            "command": " ".join(command),
        }

    try:
        parsed = _parse_nmap_xml(completed.stdout)
    except ET.ParseError:
        return {
            "available": True,
            "executed": False,
            "message": "No se pudo interpretar la salida XML de nmap.",
            "open_ports": [],
            "scanned_ports": [],
            "command": " ".join(command),
        }

    return {
        "available": True,
        "executed": True,
        "message": parsed["summary"],
        "status": parsed["status"],
        "open_ports": parsed["open_ports"],
        "scanned_ports": parsed["scanned_ports"],
        "command": " ".join(command),
    }
