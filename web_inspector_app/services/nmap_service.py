import ipaddress
import os
import shlex
import subprocess
import xml.etree.ElementTree as ET


def _nmap_result(
    available: bool,
    executed: bool,
    message: str,
    open_ports: list | None = None,
    **extra,
) -> dict:
    return {
        "available": available,
        "executed": executed,
        "message": message,
        "open_ports": open_ports or [],
        **extra,
    }


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
        return {"status": "unknown", "open_ports": [], "summary": "Nmap no devolvio informacion del host."}

    status_node = host_node.find("status")
    status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"

    open_ports = []
    for port_node in host_node.findall("./ports/port"):
        state_node = port_node.find("state")
        if state_node is None or state_node.attrib.get("state") != "open":
            continue

        service_node = port_node.find("service")
        service_attrs = service_node.attrib if service_node is not None else {}
        open_ports.append(
            {
                "port": int(port_node.attrib.get("portid", 0)),
                "protocol": port_node.attrib.get("protocol", "tcp"),
                "service": service_attrs.get("name", "desconocido"),
                "product": service_attrs.get("product", ""),
                "version": service_attrs.get("version", ""),
            }
        )

    summary = (
        f"Se han detectado {len(open_ports)} puertos abiertos."
        if open_ports
        else "No se han detectado puertos abiertos en el perfil analizado."
    )

    return {"status": status, "open_ports": open_ports, "summary": summary}


def run_nmap_scan(host: str) -> dict:
    if not _is_valid_scan_target(host):
        return _nmap_result(False, False, "El host no tiene un formato valido para ejecutar nmap.")

    raw_command = os.environ.get("NMAP_COMMAND", "nmap")
    base_command = shlex.split(raw_command, posix=False)
    command = [*base_command, "-Pn", "-T3", "--top-ports", "20", "--open", host, "-oX", "-"]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except FileNotFoundError:
        return _nmap_result(
            False,
            False,
            "Nmap no esta instalado o no se encuentra en PATH.",
            command=" ".join(command),
        )
    except subprocess.TimeoutExpired:
        return _nmap_result(
            True,
            False,
            "La ejecucion de nmap ha excedido el tiempo limite.",
            command=" ".join(command),
        )

    if completed.returncode not in (0, 1):
        stderr = completed.stderr.strip() or "Nmap ha devuelto un error inesperado."
        return _nmap_result(True, False, stderr, command=" ".join(command))

    try:
        parsed = _parse_nmap_xml(completed.stdout)
    except ET.ParseError:
        return _nmap_result(
            True,
            False,
            "No se pudo interpretar la salida XML de nmap.",
            command=" ".join(command),
        )

    return _nmap_result(
        True,
        True,
        parsed["summary"],
        parsed["open_ports"],
        status=parsed["status"],
        command=" ".join(command),
    )
