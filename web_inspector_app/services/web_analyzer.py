import html
import socket
import ssl
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


SECURITY_HEADERS = {
    "content-security-policy": "Falta Content-Security-Policy.",
    "strict-transport-security": "Falta Strict-Transport-Security.",
    "x-content-type-options": "Falta X-Content-Type-Options.",
    "x-frame-options": "Falta X-Frame-Options.",
    "referrer-policy": "Falta Referrer-Policy.",
}


class DocumentStatsParser(HTMLParser):
    def __init__(self, base_host: str) -> None:
        super().__init__()
        self.base_host = base_host
        self.forms = 0
        self.scripts = 0
        self.password_inputs = 0
        self.internal_links = 0
        self.external_links = 0
        self._in_title = False
        self._title_parts: list[str] = []
        self.meta_generator = ""

    @property
    def title(self) -> str:
        return html.unescape("".join(self._title_parts).strip())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        normalized_tag = tag.lower()

        if normalized_tag == "title":
            self._in_title = True

        if normalized_tag == "form":
            self.forms += 1

        if normalized_tag == "script":
            self.scripts += 1

        if normalized_tag == "input" and attr_map.get("type", "").lower() == "password":
            self.password_inputs += 1

        if normalized_tag == "meta":
            if attr_map.get("name", "").lower() == "generator":
                self.meta_generator = attr_map.get("content", "")

        if normalized_tag == "a":
            href = attr_map.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                return

            parsed_href = urlparse(href)
            if not parsed_href.netloc:
                self.internal_links += 1
                return

            if parsed_href.hostname == self.base_host:
                self.internal_links += 1
            else:
                self.external_links += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def _normalize_target(target: str) -> str:
    trimmed = target.strip()
    if not trimmed:
        raise ValueError("La URL o el dominio no pueden estar vacios.")

    if "://" not in trimmed:
        trimmed = f"https://{trimmed}"

    parsed = urlparse(trimmed)
    if not parsed.hostname:
        raise ValueError("No se ha podido identificar el host.")

    return trimmed


def _resolve_host(hostname: str) -> list[str]:
    addresses = []
    for item in socket.getaddrinfo(hostname, None):
        ip_address = item[4][0]
        if ip_address not in addresses:
            addresses.append(ip_address)
    return addresses


def _extract_tls_details(hostname: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()
            cipher = secure_sock.cipher()

    subject = dict(cert.get("subject", [])[0]) if cert.get("subject") else {}
    issuer = dict(cert.get("issuer", [])[0]) if cert.get("issuer") else {}

    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("commonName", ""),
        "expires_at": cert.get("notAfter", ""),
        "cipher": cipher[0] if cipher else "",
        "version": cipher[1] if cipher else "",
    }


def _build_observations(headers: dict[str, str], response_time_ms: int, is_https: bool, title: str) -> list[str]:
    observations = []
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    for header_name, message in SECURITY_HEADERS.items():
        if header_name not in normalized_headers:
            if header_name == "strict-transport-security" and not is_https:
                continue
            observations.append(message)

    if response_time_ms > 2000:
        observations.append("La pagina responde con cierta lentitud.")

    if not title:
        observations.append("No se ha encontrado un titulo HTML visible.")

    powered_by = normalized_headers.get("x-powered-by")
    if powered_by:
        observations.append(f"La cabecera X-Powered-By expone tecnologia: {powered_by}.")

    return observations


def inspect_target(target: str) -> dict[str, Any]:
    normalized_url = _normalize_target(target)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname

    started_at = time.perf_counter()
    try:
        response = requests.get(
            normalized_url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebInspector/1.0"},
        )
    except requests.RequestException as exc:
        raise ValueError(f"No se ha podido recuperar la URL: {exc}") from exc
    elapsed_ms = int((time.perf_counter() - started_at) * 1000)

    final_parsed = urlparse(response.url)
    final_host = final_parsed.hostname or hostname
    final_port = final_parsed.port or (443 if final_parsed.scheme == "https" else 80)

    try:
        ip_addresses = _resolve_host(final_host)
    except socket.gaierror as exc:
        raise ValueError("No se ha podido resolver el dominio indicado.") from exc

    parser = DocumentStatsParser(base_host=final_host)
    parser.feed(response.text[:250000])

    tls_details = None
    if response.url.startswith("https://"):
        try:
            tls_details = _extract_tls_details(final_host, final_port)
        except OSError:
            tls_details = {"error": "No se han podido leer los detalles TLS del servidor."}

    interesting_headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower()
        in {
            "server",
            "content-type",
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "x-powered-by",
            "set-cookie",
        }
    }

    observations = _build_observations(
        headers=response.headers,
        response_time_ms=elapsed_ms,
        is_https=response.url.startswith("https://"),
        title=parser.title,
    )

    robots_url = urljoin(response.url, "/robots.txt")

    return {
        "input": target,
        "normalized_url": normalized_url,
        "final_url": response.url,
        "host": final_host,
        "port": final_port,
        "ip_addresses": ip_addresses,
        "status_code": response.status_code,
        "response_time_ms": elapsed_ms,
        "title": parser.title,
        "meta_generator": parser.meta_generator,
        "forms": parser.forms,
        "scripts": parser.scripts,
        "password_inputs": parser.password_inputs,
        "internal_links": parser.internal_links,
        "external_links": parser.external_links,
        "interesting_headers": interesting_headers,
        "tls": tls_details,
        "robots_url": robots_url,
        "content_length": len(response.text),
        "observations": observations,
    }
