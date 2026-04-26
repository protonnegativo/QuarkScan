"""
QuarkScan Web UI — servidor Flask com execução de scans, streaming SSE e análise IA.

Execução:  python3 webui.py
Porta:     http://localhost:5000
"""

import json
import os
import queue
import select
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

import requests as _requests
from flask import Flask, Response, abort, jsonify, request, send_file

import storage
from security import validar_alvo, validar_args, FLAGS_PERMITIDAS

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

_HTML_PATH = os.path.join(os.path.dirname(__file__), "webui.html")


# ─── Página principal ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file(_HTML_PATH)


# ─── API de leitura ───────────────────────────────────────────────────────────

@app.route("/api/alvos")
def api_alvos():
    return jsonify(storage.alvos())


@app.route("/api/scans")
def api_scans():
    alvo      = request.args.get("alvo") or None
    ferramenta = request.args.get("ferramenta") or None
    limite    = int(request.args.get("limite", 50))
    offset    = int(request.args.get("offset", 0))
    scans     = storage.scans_paginados(alvo=alvo, ferramenta=ferramenta, limite=limite, offset=offset)
    total     = storage.total_scans(alvo=alvo, ferramenta=ferramenta)
    return jsonify({"total": total, "scans": scans})


@app.route("/api/scan/<int:scan_id>")
def api_scan_detalhe(scan_id):
    scan = storage.scan_por_id(scan_id)
    if not scan:
        abort(404, "Scan não encontrado.")
    return jsonify(scan)


@app.route("/api/vulnerabilidades")
def api_vulns():
    alvo = request.args.get("alvo", "")
    if not alvo:
        abort(400, "Parâmetro 'alvo' obrigatório.")
    return jsonify(storage.vulns_conhecidas(alvo))


@app.route("/api/ferramentas")
def api_ferramentas():
    with storage._conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT ferramenta FROM resultados ORDER BY ferramenta"
        ).fetchall()
    return jsonify([r["ferramenta"] for r in rows])


@app.route("/api/stats")
def api_stats():
    with storage._conn() as conn:
        total_scans  = conn.execute("SELECT COUNT(*) AS n FROM resultados").fetchone()["n"]
        total_alvos  = conn.execute("SELECT COUNT(DISTINCT alvo) AS n FROM resultados").fetchone()["n"]
        total_vulns  = conn.execute("SELECT COUNT(*) AS n FROM vulnerabilidades WHERE status!='falso-positivo'").fetchone()["n"]
        vulns_crit   = conn.execute("SELECT COUNT(*) AS n FROM vulnerabilidades WHERE severidade='critical' AND status!='falso-positivo'").fetchone()["n"]
        vulns_high   = conn.execute("SELECT COUNT(*) AS n FROM vulnerabilidades WHERE severidade='high' AND status!='falso-positivo'").fetchone()["n"]
    return jsonify({
        "total_scans": total_scans, "total_alvos": total_alvos,
        "total_vulns": total_vulns, "vulns_criticas": vulns_crit, "vulns_altas": vulns_high,
    })


# ─── Execução de scans direta (sem LLM) ──────────────────────────────────────

def _build_command(ferramenta: str, alvo: str, opts: dict) -> list[str]:
    """Monta o comando para cada ferramenta com base nas opções recebidas."""
    if ferramenta == "nmap":
        args_str = opts.get("argumentos", "-sT --top-ports 1000")
        args_validados = validar_args(args_str)
        if not args_validados:
            raise ValueError(f"Argumentos nmap inválidos. Flags permitidas: {', '.join(sorted(FLAGS_PERMITIDAS))}")
        # --stats-every emite progresso periódico no stderr (visível no terminal)
        return ["nmap", "--stats-every", "5s"] + args_validados + [alvo]

    if ferramenta == "gobuster":
        wordlists = {
            "small":  "/usr/share/dirb/wordlists/small.txt",
            "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "big":    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        }
        wl   = wordlists.get(opts.get("wordlist", "common"), wordlists["common"])
        proto = opts.get("protocolo", "https")
        cmd = ["gobuster", "dir", "-u", f"{proto}://{alvo}", "-w", wl,
               "-q", "--no-error", "-t", str(opts.get("threads", 20)), "--timeout", "10s", "-k"]
        ext = opts.get("extensoes", "")
        if ext:
            cmd += ["-x", ext]
        return cmd

    if ferramenta == "nikto":
        porta = str(opts.get("porta", "443"))
        cmd = ["nikto", "-h", alvo, "-p", porta, "-maxtime", "300s", "-nointeractive", "-Format", "txt"]
        if opts.get("ssl", porta == "443"):
            cmd.append("-ssl")
        return cmd

    if ferramenta == "nuclei":
        sev = opts.get("severidade", "critical,high,medium")
        cmd = ["nuclei", "-u", f"https://{alvo}", "-severity", sev,
               "-rate-limit", str(opts.get("rate_limit", 150)),
               "-timeout", str(opts.get("timeout", 5)), "-silent", "-no-color"]
        tags = opts.get("tags", "")
        if tags:
            cmd += ["-tags", tags]
        return cmd

    if ferramenta == "whatweb":
        nivel = str(opts.get("agressividade", 1))
        return ["whatweb", f"-a{nivel}", "--no-errors", "--color=never", f"https://{alvo}"]

    if ferramenta == "subfinder":
        cmd = ["subfinder", "-d", alvo, "-silent", "-timeout", "30", "-t", "10"]
        if opts.get("recursivo"):
            cmd.append("-recursive")
        return cmd

    raise ValueError(f"Ferramenta desconhecida: {ferramenta}")


def _run_scan_streaming(ferramenta: str, alvo: str, opts: dict, q: queue.Queue):
    """Executa o scan em thread separada e envia linhas para a fila."""
    try:
        comando = _build_command(ferramenta, alvo, opts)
        q.put({"type": "cmd", "data": " ".join(comando)})

        inicio = time.time()
        raw_lines = []

        # stdbuf -oL força line-buffering no stdout do processo filho,
        # necessário pois ferramentas como nmap/gobuster bufferizam quando
        # não estão em TTY. stderr separado para capturar progresso do nmap.
        proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL"] + comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        while True:
            fds = select.select([proc.stdout, proc.stderr], [], [], 1.0)[0]
            for fd in fds:
                linha = fd.readline()
                if linha:
                    texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                    raw_lines.append(texto)
                    q.put({"type": "line", "data": texto})
            if proc.poll() is not None:
                # Drena o que sobrou nos buffers
                for fd in [proc.stdout, proc.stderr]:
                    for linha in fd:
                        texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                        if texto:
                            raw_lines.append(texto)
                            q.put({"type": "line", "data": texto})
                break

        proc.wait()
        duracao_ms = int((time.time() - inicio) * 1000)
        raw_output = "\n".join(raw_lines)

        # Salva no banco com raw_output preenchido, resultado = mesmo conteúdo
        storage.salvar(
            alvo, ferramenta, raw_output,
            parametros={**opts, "via": "webui"},
            raw_output=raw_output,
        )
        storage.salvar_metrica(ferramenta, alvo, proc.returncode, duracao_ms, proc.returncode == 0)

        scan_id = storage.ultimo_id(alvo, ferramenta)
        q.put({"type": "done", "exit_code": proc.returncode, "duracao_ms": duracao_ms, "scan_id": scan_id})

    except ValueError as e:
        q.put({"type": "error", "data": str(e)})
    except FileNotFoundError:
        q.put({"type": "error", "data": f"Ferramenta '{ferramenta}' não encontrada no sistema."})
    except Exception as e:
        q.put({"type": "error", "data": str(e)})


@app.route("/api/run")
def api_run():
    """SSE endpoint — executa um scan e faz streaming do output linha a linha.

    Query params:
        alvo        (obrigatório)
        ferramenta  (obrigatório): nmap | gobuster | nikto | nuclei | whatweb | subfinder
        + parâmetros específicos da ferramenta (argumentos, wordlist, porta, etc.)
    """
    alvo = request.args.get("alvo", "").strip()
    ferramenta = request.args.get("ferramenta", "").strip()

    if not alvo or not ferramenta:
        abort(400, "Parâmetros 'alvo' e 'ferramenta' são obrigatórios.")

    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        abort(400, "Alvo inválido. Use domínio ou IP.")

    opts = {k: v for k, v in request.args.items() if k not in ("alvo", "ferramenta")}

    q = queue.Queue()
    t = threading.Thread(target=_run_scan_streaming, args=(ferramenta, alvo_limpo, opts, q), daemon=True)
    t.start()

    def generate():
        while True:
            try:
                msg = q.get(timeout=120)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg["type"] in ("done", "error"):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Análise IA sobre todos os resultados de um alvo ─────────────────────────

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Chama o LLM mestre com todos os raw_outputs do alvo e salva llm_analysis."""
    body = request.get_json(force=True, silent=True) or {}
    alvo = (body.get("alvo") or "").strip()
    scan_ids = body.get("scan_ids") or []  # lista de IDs específicos (opcional)

    if not alvo:
        abort(400, "Campo 'alvo' obrigatório.")

    # Busca scans — específicos ou todos do alvo
    if scan_ids:
        scans = [storage.scan_por_id(i) for i in scan_ids if storage.scan_por_id(i)]
    else:
        scans = storage.historico(alvo, limite=30)

    if not scans:
        abort(404, "Nenhum scan encontrado para este alvo.")

    # Monta o contexto para o LLM
    blocos = []
    for s in scans:
        conteudo = s.get("raw_output") or s.get("resultado") or ""
        if conteudo:
            blocos.append(f"=== {s['ferramenta'].upper()} [{s['timestamp']}] ===\n{conteudo[:4000]}")

    if not blocos:
        abort(422, "Nenhum output disponível para análise.")

    contexto = "\n\n".join(blocos)
    prompt = f"""Você é um especialista em segurança ofensiva. Analise os resultados abaixo de múltiplas ferramentas de pentest executadas contra o alvo "{alvo}" e produza um relatório consolidado.

RESULTADOS DOS SCANS:
{contexto}

Produza um relatório estruturado com:
1. **Resumo Executivo** — visão geral em 3-5 linhas
2. **Superfície de Ataque** — portas, serviços e tecnologias identificadas
3. **Vulnerabilidades e Riscos** — agrupados por severidade (Crítico / Alto / Médio / Baixo)
4. **Vetores de Ataque Prioritários** — top 3 caminhos mais promissores
5. **Recomendações** — ações imediatas e de médio prazo

Seja técnico, direto e baseie-se exclusivamente nos dados fornecidos."""

    try:
        from llm import criar_llm
        llm = criar_llm("supervisor")
        resposta = llm.invoke(prompt)
        analise = getattr(resposta, "content", str(resposta)).strip()
    except Exception as e:
        abort(500, f"Erro ao chamar o LLM: {e}")

    # Salva llm_analysis em cada scan referenciado
    ids_atualizados = []
    for s in scans:
        storage.salvar_llm_analysis(s["id"], analise)
        ids_atualizados.append(s["id"])

    return jsonify({"analise": analise, "scan_ids": ids_atualizados})


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("WEBUI_PORT", 5000))
    host = os.environ.get("WEBUI_HOST", "0.0.0.0")
    print(f"[QuarkScan Web UI] http://localhost:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
