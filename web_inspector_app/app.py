from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

from services.nmap_service import run_nmap_scan
from services.web_analyzer import inspect_target


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/inspect")
def inspect():
    payload = request.get_json(silent=True) or request.form.to_dict()
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"ok": False, "error": "Indica una URL o un dominio para analizar."}), 400

    try:
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

    return jsonify(
        {
            "ok": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "web": web_report,
            "nmap": nmap_report,
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
