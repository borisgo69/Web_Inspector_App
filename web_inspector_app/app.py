import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from services.nmap_service import run_nmap_scan
from services.web_analyzer import inspect_target


app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
HISTORY_PATH = BASE_DIR / "data" / "scan_history.json"
HISTORY_LIMIT = 20
history_lock = Lock()


def _extract_host(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or "").strip()


def _looks_like_invalid_ip(host: str) -> bool:
    if ":" in host:
        return True

    return "." in host and all(char.isdigit() or char == "." for char in host)


def _is_valid_domain(host: str) -> bool:
    if len(host) > 253:
        return False

    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False

    return True


def _validate_target(target: str) -> None:
    host = _extract_host(target)

    if not host:
        raise ValueError("Dirección IP no válida")

    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass

    if _looks_like_invalid_ip(host) or not _is_valid_domain(host):
        raise ValueError("Dirección IP no válida")


def _load_scan_history() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []

    try:
        with HISTORY_PATH.open("r", encoding="utf-8") as history_file:
            data = json.load(history_file)
    except (OSError, json.JSONDecodeError):
        return []

    return data if isinstance(data, list) else []


def _write_scan_history(history: list[dict]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("w", encoding="utf-8") as history_file:
        json.dump(history[:HISTORY_LIMIT], history_file, indent=2, ensure_ascii=False)


def _build_history_entry(report: dict) -> dict:
    web_report = report["web"]
    nmap_report = report["nmap"]

    return {
        "generated_at": report["generated_at"],
        "target": web_report["input"],
        "host": web_report["host"],
        "final_url": web_report["final_url"],
        "status_code": web_report["status_code"],
        "response_time_ms": web_report["response_time_ms"],
        "open_ports": len(nmap_report.get("open_ports", [])),
        "command": nmap_report.get("command", ""),
    }


def _save_scan_history(report: dict) -> list[dict]:
    with history_lock:
        history = _load_scan_history()
        history.insert(0, _build_history_entry(report))
        history = history[:HISTORY_LIMIT]
        _write_scan_history(history)
        return history


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/history")
def history():
    return jsonify({"ok": True, "history": _load_scan_history()})


@app.post("/api/inspect")
def inspect():
    payload = request.get_json(silent=True) or request.form.to_dict()
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"ok": False, "error": "Indica una IP, URL o dominio para analizar."}), 400

    try:
        _validate_target(target)
        web_report = inspect_target(target)
        nmap_report = run_nmap_scan(web_report["host"])
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": "La inspeccion ha fallado.",
                "details": str(exc),
            }
        ), 500

    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "web": web_report,
        "nmap": nmap_report,
    }
    report["history"] = _save_scan_history(report)

    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True)
