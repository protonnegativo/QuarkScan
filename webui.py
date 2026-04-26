"""
QuarkScan Web UI — servidor Flask leve para visualização de scans.

Execução:  python webui.py
Porta:     http://localhost:5000
"""

import json
import os
import sys

# Garante que o módulo storage seja encontrado mesmo ao rodar de fora do diretório
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, abort, jsonify, render_template_string, request

import storage

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ─── Template HTML (embutido para ser self-contained) ─────────────────────────
_HTML = open(os.path.join(os.path.dirname(__file__), "webui.html")).read()


@app.route("/")
def index():
    return _HTML


# ─── API ──────────────────────────────────────────────────────────────────────

@app.route("/api/alvos")
def api_alvos():
    """Lista todos os alvos com contagem e ferramentas usadas."""
    return jsonify(storage.alvos())


@app.route("/api/scans")
def api_scans():
    """Lista scans com paginação opcional.
    Query params: alvo, ferramenta, limite (default 50), offset (default 0)
    """
    alvo = request.args.get("alvo") or None
    ferramenta = request.args.get("ferramenta") or None
    limite = int(request.args.get("limite", 50))
    offset = int(request.args.get("offset", 0))
    scans = storage.scans_paginados(alvo=alvo, ferramenta=ferramenta, limite=limite, offset=offset)
    total = storage.total_scans(alvo=alvo, ferramenta=ferramenta)
    return jsonify({"total": total, "scans": scans})


@app.route("/api/scan/<int:scan_id>")
def api_scan_detalhe(scan_id: int):
    """Retorna o scan completo: resultado, raw_output e llm_analysis."""
    scan = storage.scan_por_id(scan_id)
    if not scan:
        abort(404, "Scan não encontrado.")
    return jsonify(scan)


@app.route("/api/vulnerabilidades")
def api_vulns():
    """Lista vulnerabilidades por alvo."""
    alvo = request.args.get("alvo", "")
    if not alvo:
        abort(400, "Parâmetro 'alvo' obrigatório.")
    rows = storage.vulns_conhecidas(alvo)
    return jsonify(rows)


@app.route("/api/ferramentas")
def api_ferramentas():
    """Retorna lista de ferramentas distintas no banco."""
    with storage._conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT ferramenta FROM resultados ORDER BY ferramenta"
        ).fetchall()
    return jsonify([r["ferramenta"] for r in rows])


@app.route("/api/stats")
def api_stats():
    """Resumo geral: total de scans, alvos, vulnerabilidades."""
    with storage._conn() as conn:
        total_scans = conn.execute("SELECT COUNT(*) AS n FROM resultados").fetchone()["n"]
        total_alvos = conn.execute("SELECT COUNT(DISTINCT alvo) AS n FROM resultados").fetchone()["n"]
        total_vulns = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilidades WHERE status != 'falso-positivo'"
        ).fetchone()["n"]
        vulns_criticas = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilidades WHERE severidade='critical' AND status != 'falso-positivo'"
        ).fetchone()["n"]
        vulns_altas = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilidades WHERE severidade='high' AND status != 'falso-positivo'"
        ).fetchone()["n"]
    return jsonify({
        "total_scans": total_scans,
        "total_alvos": total_alvos,
        "total_vulns": total_vulns,
        "vulns_criticas": vulns_criticas,
        "vulns_altas": vulns_altas,
    })


if __name__ == "__main__":
    port = int(os.environ.get("WEBUI_PORT", 5000))
    host = os.environ.get("WEBUI_HOST", "0.0.0.0")
    print(f"[QuarkScan Web UI] http://localhost:{port}")
    app.run(host=host, port=port, debug=False)
