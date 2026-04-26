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

# Projeto ativo global (por instância do servidor)
_projeto_ativo: dict | None = None  # {"id": int, "nome": str}

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
        args_str = opts.get("argumentos", "-sT -p- --open")
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
        sev = opts.get("severidade", "info,low,medium,high,critical")
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
        if _projeto_ativo:
            storage.projeto_adicionar_alvo(_projeto_ativo["id"], alvo)
        q.put({"type": "done", "exit_code": proc.returncode, "duracao_ms": duracao_ms, "scan_id": scan_id, "projeto_ativo": _projeto_ativo})

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


# ─── Projetos ─────────────────────────────────────────────────────────────────

@app.route("/api/projetos", methods=["GET"])
def api_projetos_listar():
    return jsonify(storage.projetos_listar())


@app.route("/api/projetos", methods=["POST"])
def api_projeto_criar():
    body = request.get_json(force=True, silent=True) or {}
    nome = (body.get("nome") or "").strip()
    if not nome:
        abort(400, "Campo 'nome' obrigatório.")
    pid = storage.projeto_criar(nome, body.get("descricao", ""))
    # Adiciona alvos iniciais se informados
    for alvo in body.get("alvos", []):
        a = validar_alvo(alvo)
        if a:
            storage.projeto_adicionar_alvo(pid, a)
    return jsonify({"id": pid}), 201


@app.route("/api/projetos/<int:pid>", methods=["PUT"])
def api_projeto_atualizar(pid):
    body = request.get_json(force=True, silent=True) or {}
    storage.projeto_atualizar(pid, body.get("nome"), body.get("descricao"))
    return jsonify({"ok": True})


@app.route("/api/projetos/<int:pid>", methods=["DELETE"])
def api_projeto_deletar(pid):
    storage.projeto_deletar(pid)
    return jsonify({"ok": True})


@app.route("/api/projetos/<int:pid>/alvos", methods=["POST"])
def api_projeto_add_alvo(pid):
    body = request.get_json(force=True, silent=True) or {}
    alvo = validar_alvo((body.get("alvo") or "").strip())
    if not alvo:
        abort(400, "Alvo inválido.")
    storage.projeto_adicionar_alvo(pid, alvo)
    return jsonify({"ok": True})


@app.route("/api/projetos/<int:pid>/alvos/<path:alvo>", methods=["DELETE"])
def api_projeto_remove_alvo(pid, alvo):
    storage.projeto_remover_alvo(pid, alvo)
    return jsonify({"ok": True})


@app.route("/api/alvos/buscar")
def api_alvos_buscar():
    """Busca alvos no banco que contenham o termo."""
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])
    return jsonify(storage.alvos_por_dominio(q))


@app.route("/api/projetos/<int:pid>/contexto")
def api_projeto_contexto(pid):
    """Retorna dados completos do projeto: alvos, scans recentes, vulnerabilidades."""
    projs = storage.projetos_listar()
    proj = next((p for p in projs if p["id"] == pid), None)
    if not proj:
        abort(404, "Projeto não encontrado.")
    alvos = proj.get("alvos") or []
    scans = []
    vulns = []
    for alvo in alvos:
        scans += storage.historico(alvo, limite=20)
        vulns += storage.vulns_conhecidas(alvo)
    # Stats por alvo
    stats_alvos = []
    for alvo in alvos:
        rows = storage.historico(alvo, limite=100)
        tools = list({r["ferramenta"] for r in rows})
        stats_alvos.append({
            "alvo": alvo,
            "total_scans": len(rows),
            "ferramentas": tools,
            "ultimo_scan": rows[0]["timestamp"] if rows else None,
        })
    return jsonify({
        "projeto": proj,
        "stats_alvos": stats_alvos,
        "scans": sorted(scans, key=lambda x: x["timestamp"], reverse=True)[:50],
        "vulnerabilidades": vulns,
    })


@app.route("/api/projetos/<int:pid>/chat", methods=["POST"])
def api_projeto_chat(pid):
    """Chat SSE com contexto completo do projeto injetado no prompt."""
    body = request.get_json(force=True, silent=True) or {}
    mensagem = (body.get("mensagem") or "").strip()
    session_id = f"proj_{pid}"

    if not mensagem:
        abort(400, "Campo 'mensagem' obrigatório.")

    from security import sanitizar_input
    mensagem = sanitizar_input(mensagem)

    # Constrói contexto do projeto
    projs = storage.projetos_listar()
    proj = next((p for p in projs if p["id"] == pid), None)
    alvos = proj.get("alvos", []) if proj else []

    blocos_ctx = []
    for alvo in alvos[:10]:
        scans = storage.historico(alvo, limite=5)
        for s in scans:
            conteudo = s.get("raw_output") or s.get("resultado") or ""
            if conteudo:
                blocos_ctx.append(f"[{alvo} / {s['ferramenta']} / {s['timestamp']}]\n{conteudo[:2000]}")

    vulns = []
    for alvo in alvos:
        vulns += storage.vulns_conhecidas(alvo)

    sistema = f"""Você é um especialista em segurança ofensiva assistindo um pentester que trabalha no projeto "{proj['nome'] if proj else 'desconhecido'}".

ALVOS DO PROJETO: {', '.join(alvos) if alvos else 'nenhum'}

VULNERABILIDADES CONHECIDAS ({len(vulns)} total):
{chr(10).join(f"- [{v.get('severidade','?').upper()}] {v.get('subdominio','')} — {v.get('tipo','')} — {v.get('identificador','')}" for v in vulns[:20]) if vulns else 'Nenhuma registrada.'}

ÚLTIMOS RESULTADOS DE SCANS:
{chr(10).join(blocos_ctx[:8]) if blocos_ctx else 'Nenhum scan disponível.'}

Responda de forma técnica, direta e baseando-se nos dados acima. Quando sugerir próximos passos, seja específico com comandos."""

    storage.chat_salvar_mensagem(session_id, "user", mensagem)

    q = queue.Queue()

    def _run():
        try:
            from agents.supervisor import supervisor
            config = {"configurable": {"thread_id": session_id}}
            prompt_completo = f"{sistema}\n\n---\nPergunta do pentester: {mensagem}"
            resposta = supervisor.invoke({"messages": [("user", prompt_completo)]}, config=config)
            conteudo = resposta["messages"][-1].content
            if isinstance(conteudo, list):
                texto = "\n".join(
                    item.get("text", "") if isinstance(item, dict) else str(item)
                    for item in conteudo
                ).strip()
            else:
                texto = str(conteudo or "").strip()
            storage.chat_salvar_mensagem(session_id, "assistant", texto)
            q.put({"type": "chunk", "data": texto})
            q.put({"type": "done"})
        except Exception as e:
            q.put({"type": "error", "data": str(e)})

    threading.Thread(target=_run, daemon=True).start()

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


@app.route("/api/projeto-ativo", methods=["GET"])
def api_projeto_ativo_get():
    return jsonify(_projeto_ativo)


@app.route("/api/projeto-ativo", methods=["POST"])
def api_projeto_ativo_set():
    global _projeto_ativo
    body = request.get_json(force=True, silent=True) or {}
    if body.get("limpar"):
        _projeto_ativo = None
    else:
        pid  = body.get("id")
        nome = body.get("nome", "")
        if pid:
            _projeto_ativo = {"id": int(pid), "nome": nome}
        else:
            _projeto_ativo = None
    return jsonify(_projeto_ativo)


@app.route("/api/alvos/todos")
def api_alvos_todos():
    """Lista todos os alvos distintos com metadados (para página Alvos)."""
    return jsonify(storage.alvos_todos())


@app.route("/api/projetos/<int:pid>/adicionar-alvos", methods=["POST"])
def api_projeto_adicionar_alvos(pid):
    """Adiciona múltiplos alvos a um projeto de uma vez."""
    body = request.get_json(force=True, silent=True) or {}
    alvos = body.get("alvos", [])
    adicionados = 0
    for alvo in alvos:
        a = validar_alvo(str(alvo).strip())
        if a:
            storage.projeto_adicionar_alvo(pid, a)
            adicionados += 1
    return jsonify({"adicionados": adicionados})


# ─── Chat com o Agente ────────────────────────────────────────────────────────

@app.route("/api/chat/sessoes")
def api_chat_sessoes():
    return jsonify(storage.chat_sessoes())


@app.route("/api/chat/<session_id>/historico")
def api_chat_historico(session_id):
    return jsonify(storage.chat_historico_sessao(session_id))


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """SSE — envia mensagem ao supervisor LangGraph e faz streaming da resposta."""
    body = request.get_json(force=True, silent=True) or {}
    mensagem = (body.get("mensagem") or "").strip()
    session_id = (body.get("session_id") or "default").strip()

    if not mensagem:
        abort(400, "Campo 'mensagem' obrigatório.")

    from security import sanitizar_input
    mensagem = sanitizar_input(mensagem)

    # Salva mensagem do usuário
    storage.chat_salvar_mensagem(session_id, "user", mensagem)

    q = queue.Queue()

    def _run_agent():
        try:
            import uuid
            from agents.supervisor import supervisor
            config = {"configurable": {"thread_id": session_id}}
            resposta = supervisor.invoke({"messages": [("user", mensagem)]}, config=config)
            conteudo = resposta["messages"][-1].content
            if isinstance(conteudo, list):
                texto = "\n".join(
                    item.get("text", "") if isinstance(item, dict) else str(item)
                    for item in conteudo
                ).strip()
            else:
                texto = str(conteudo or "").strip()
            storage.chat_salvar_mensagem(session_id, "assistant", texto)
            q.put({"type": "chunk", "data": texto})
            q.put({"type": "done"})
        except Exception as e:
            q.put({"type": "error", "data": str(e)})

    threading.Thread(target=_run_agent, daemon=True).start()

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


# ─── Autopilot (PTES pipeline com decisões IA entre fases) ───────────────────

def _extract_open_ports(nmap_output: str) -> list[str]:
    """Extrai portas abertas do output do nmap (ex: '80/tcp open http' → ['80'])."""
    import re
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"^\s*(\d+)/tcp\s+open", line)
        if m:
            ports.append(m.group(1))
    return ports


def _extract_http_ports(nmap_output: str) -> list[str]:
    """Retorna portas com serviços web (http/https/ssl)."""
    import re
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"^\s*(\d+)/tcp\s+open\s+(\S+)", line)
        if m and any(kw in m.group(2).lower() for kw in ("http", "ssl", "web")):
            ports.append(m.group(1))
    return ports or ["80", "443"]


def _ai_decide_next_phase(phase_name: str, phase_output: str, alvo: str) -> dict:
    """Chama o LLM para decidir os parâmetros da próxima fase."""
    try:
        from llm import criar_llm
        llm = criar_llm("supervisor")
        prompt = f"""Você é um especialista em pentest automatizado seguindo metodologia PTES.

Alvo: {alvo}
Fase concluída: {phase_name}
Output:
{phase_output[:3000]}

Responda APENAS com um JSON válido (sem markdown, sem explicação) contendo os parâmetros
para a próxima fase. Exemplo de formato:
{{"argumentos": "-sV -sC -p 22,80,443", "portas": ["80", "443"], "protocolo": "https"}}

Se não houver dados suficientes para decidir, retorne {{}}."""
        resposta = llm.invoke(prompt)
        conteudo = getattr(resposta, "content", str(resposta)).strip()
        import re, json as _json
        m = re.search(r"\{.*\}", conteudo, re.DOTALL)
        if m:
            return _json.loads(m.group(0))
    except Exception:
        pass
    return {}


def _run_phase(ferramenta: str, alvo: str, opts: dict) -> tuple[int, str]:
    """Executa uma ferramenta e retorna (exit_code, raw_output)."""
    import subprocess, time
    try:
        comando = _build_command(ferramenta, alvo, opts)
        inicio = time.time()
        proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL"] + comando,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        )
        stdout, stderr = proc.communicate(timeout=600)
        duracao_ms = int((time.time() - inicio) * 1000)
        raw = (stdout + stderr).decode("utf-8", errors="replace")
        storage.salvar(alvo, ferramenta, raw, parametros={**opts, "via": "autopilot"}, raw_output=raw)
        storage.salvar_metrica(ferramenta, alvo, proc.returncode, duracao_ms, proc.returncode == 0)
        return proc.returncode, raw
    except Exception as e:
        return 1, str(e)


def _scan_alvo_pipeline(alvo_atual: str, emit, via_label: str = "autopilot"):
    """Executa o pipeline completo (nmap→whatweb→nikto/nuclei→gobuster) para UM alvo.
    Retorna o raw_output consolidado de todos os scans desse alvo."""

    def run_tool(ferramenta: str, opts: dict) -> str | None:
        try:
            comando = _build_command(ferramenta, alvo_atual, opts)
            emit("cmd", data=f"[{alvo_atual}] $ {' '.join(comando)}")
        except ValueError as e:
            emit("error", data=str(e))
            return None

        raw_lines = []
        inicio = time.time()
        try:
            proc = subprocess.Popen(
                ["stdbuf", "-oL", "-eL"] + comando,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            )
            while True:
                fds = select.select([proc.stdout, proc.stderr], [], [], 1.0)[0]
                for fd in fds:
                    linha = fd.readline()
                    if linha:
                        texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                        raw_lines.append(texto)
                        emit("line", data=texto)
                if proc.poll() is not None:
                    for fd in [proc.stdout, proc.stderr]:
                        for linha in fd:
                            texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                            if texto:
                                raw_lines.append(texto)
                                emit("line", data=texto)
                    break
            proc.wait()
            duracao_ms = int((time.time() - inicio) * 1000)
            raw = "\n".join(raw_lines)
            storage.salvar(alvo_atual, ferramenta, raw,
                           parametros={"via": via_label}, raw_output=raw)
            storage.salvar_metrica(ferramenta, alvo_atual, proc.returncode, duracao_ms, proc.returncode == 0)
            scan_id = storage.ultimo_id(alvo_atual, ferramenta)
            emit("phase_done", ferramenta=ferramenta, alvo=alvo_atual,
                 scan_id=scan_id, duracao_ms=duracao_ms, exit_code=proc.returncode)
            return raw
        except FileNotFoundError:
            emit("info", data=f"Ferramenta '{ferramenta}' não encontrada — pulando.")
            return None
        except Exception as e:
            emit("info", data=f"Erro em {ferramenta}: {e}")
            return None

    # Fase 1 nmap: todas as portas, reporta só abertas
    nmap_quick = run_tool("nmap", {"argumentos": "-sT -p- --open"}) or ""

    # Fase 2 nmap: -sV -sC em todas as portas abertas encontradas
    open_ports = _extract_open_ports(nmap_quick)
    if open_ports:
        ports_str = ",".join(open_ports)
        emit("ai_thinking", data=f"[{alvo_atual}] {len(open_ports)} porta(s) abertas — rodando -sV -sC nelas…")
        nmap_args = f"-sV -sC -p {ports_str}"
    else:
        nmap_args = "-sV -sC -p-"
    emit("ai_decision", data=f"[{alvo_atual}] nmap fase 2: {nmap_args}")
    nmap_sv = run_tool("nmap", {"argumentos": nmap_args}) or ""

    # Fingerprinting web
    run_tool("whatweb", {"agressividade": 1})

    # Decide porta/protocolo para scans web
    http_ports = _extract_http_ports(nmap_sv) or _extract_http_ports(nmap_quick)
    ai_nikto = _ai_decide_next_phase("service detection", nmap_sv, alvo_atual)
    porta_nikto = ai_nikto.get("porta", http_ports[0] if http_ports else "443")
    use_ssl = str(porta_nikto) in ("443", "8443") or bool(ai_nikto.get("ssl"))
    emit("ai_decision", data=f"[{alvo_atual}] web: porta {porta_nikto} SSL={use_ssl}")

    run_tool("nikto", {"porta": str(porta_nikto), "ssl": "1" if use_ssl else ""})
    run_tool("nuclei", {"severidade": "info,low,medium,high,critical"})

    proto = "https" if use_ssl else "http"
    run_tool("gobuster", {"protocolo": proto, "wordlist": "common", "threads": 20})

    # Adiciona ao projeto ativo
    if _projeto_ativo:
        storage.projeto_adicionar_alvo(_projeto_ativo["id"], alvo_atual)

    return nmap_sv or nmap_quick


def _autopilot_pipeline(alvo: str, q: queue.Queue):
    """Pipeline PTES completo: subfinder → pipeline por subdomínio → relatório IA."""
    def emit(tipo, **kwargs):
        q.put({"type": tipo, **kwargs})

    todos_alvos_scaneados = []

    try:
        # ── Fase 1: Descoberta de subdomínios ─────────────────────────────
        emit("phase_header", text="Fase 1 — Reconhecimento Passivo (subfinder)")

        raw_sf_lines = []
        inicio = time.time()
        try:
            proc = subprocess.Popen(
                ["stdbuf", "-oL", "-eL"] + _build_command("subfinder", alvo, {}),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            )
            while True:
                fds = select.select([proc.stdout, proc.stderr], [], [], 1.0)[0]
                for fd in fds:
                    linha = fd.readline()
                    if linha:
                        texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                        raw_sf_lines.append(texto)
                        emit("line", data=texto)
                if proc.poll() is not None:
                    for fd in [proc.stdout, proc.stderr]:
                        for linha in fd:
                            texto = linha.decode("utf-8", errors="replace").rstrip("\n")
                            if texto:
                                raw_sf_lines.append(texto)
                                emit("line", data=texto)
                    break
            proc.wait()
        except Exception as e:
            emit("info", data=f"subfinder: {e}")

        sf_raw = "\n".join(raw_sf_lines)
        storage.salvar(alvo, "subfinder", sf_raw, parametros={"via": "autopilot"}, raw_output=sf_raw)
        if _projeto_ativo:
            storage.projeto_adicionar_alvo(_projeto_ativo["id"], alvo)

        # Extrai subdomínios válidos do output
        subdomains = sorted({
            s.strip().lower() for s in raw_sf_lines
            if s.strip() and alvo in s.strip() and s.strip() != alvo
            and not s.strip().startswith("[") and " " not in s.strip()
        })
        emit("info", data=f"Subdomínios encontrados: {len(subdomains)} — {', '.join(subdomains[:10])}{'…' if len(subdomains)>10 else ''}")

        # Lista de alvos: domínio raiz + subdomínios (máx 10 para não explodir)
        alvos_pipeline = [alvo] + subdomains[:10]
        emit("phase_header", text=f"Iniciando pipeline para {len(alvos_pipeline)} alvo(s): {', '.join(alvos_pipeline)}")

        # ── Fase 2-6 para cada alvo ────────────────────────────────────────
        for i, alvo_atual in enumerate(alvos_pipeline, 1):
            emit("phase_header", text=f"[{i}/{len(alvos_pipeline)}] Pipeline PTES → {alvo_atual}")
            _scan_alvo_pipeline(alvo_atual, emit)
            todos_alvos_scaneados.append(alvo_atual)
            emit("alvo_concluido", alvo=alvo_atual, index=i, total=len(alvos_pipeline))

        # ── Relatório final consolidado ────────────────────────────────────
        emit("phase_header", text="Relatório Final Consolidado — IA analisando todos os alvos")
        emit("ai_thinking", data="LLM consolidando resultados de todos os subdomínios…")

        blocos = []
        for a in todos_alvos_scaneados:
            scans = storage.historico(a, limite=6)
            for s in scans:
                conteudo = s.get("raw_output") or s.get("resultado") or ""
                if conteudo:
                    blocos.append(f"=== {a} / {s['ferramenta'].upper()} ===\n{conteudo[:2000]}")

        if blocos:
            try:
                from llm import criar_llm
                llm = criar_llm("supervisor")
                alvos_str = ", ".join(todos_alvos_scaneados)
                prompt = f"""Você é um especialista em pentest. Analise o pipeline PTES completo abaixo para o domínio "{alvo}" e seus subdomínios ({alvos_str}) e produza um relatório consolidado:

1. Resumo Executivo
2. Superfície de Ataque (por subdomínio)
3. Vulnerabilidades por severidade (Crítico / Alto / Médio)
4. Top 3 Vetores de Ataque mais promissores
5. Recomendações Imediatas por prioridade

RESULTADOS:
{chr(10).join(blocos[:20])}"""
                resposta = llm.invoke(prompt)
                analise = getattr(resposta, "content", str(resposta)).strip()
                for a in todos_alvos_scaneados:
                    scans = storage.historico(a, limite=6)
                    for s in scans:
                        storage.salvar_llm_analysis(s["id"], analise)
                emit("final_report", data=analise)
            except Exception as e:
                emit("info", data=f"Relatório IA falhou: {e}")

        emit("done", message=f"Pipeline PTES concluído para {len(todos_alvos_scaneados)} alvo(s).",
             projeto_ativo=_projeto_ativo, alvos=todos_alvos_scaneados)

    except Exception as e:
        emit("error", data=f"Autopilot falhou: {e}")


@app.route("/api/autopilot")
def api_autopilot():
    """SSE endpoint — executa o pipeline PTES completo com IA entre fases."""
    alvo = request.args.get("alvo", "").strip()
    if not alvo:
        abort(400, "Parâmetro 'alvo' obrigatório.")
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        abort(400, "Alvo inválido. Use domínio ou IP.")

    q = queue.Queue()
    t = threading.Thread(target=_autopilot_pipeline, args=(alvo_limpo, q), daemon=True)
    t.start()

    def generate():
        while True:
            try:
                msg = q.get(timeout=300)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg["type"] in ("done", "error"):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("WEBUI_PORT", 5000))
    host = os.environ.get("WEBUI_HOST", "0.0.0.0")
    print(f"[QuarkScan Web UI] http://localhost:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
