"""
pipeline_graph.py — Pipeline autônomo baseado em LangGraph StateGraph.

Substitui pipeline.py com:
  - Estado tipado compartilhado entre todos os nós
  - Fallback automático: subfinder vazio → DNS brute-force
  - Gate de confirmação interativo antes de fases destrutivas
  - Checkpointing via MemorySaver para retomada após falha
"""
from __future__ import annotations

import re
from typing import Annotated, Callable, Optional
from operator import add

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from agents.base import extrair_conteudo
from terminal import C, formatar_para_terminal

_SEP2 = chr(9552) * 60
_SEP  = chr(9472) * 60


# ─── Estado compartilhado ─────────────────────────────────────────────────────

class PipelineState(dict):
    """
    Estado do pipeline. Campos com Annotated[list, add] acumulam resultados
    de nós paralelos sem sobrescrever — requisito do LangGraph para fan-out.
    """
    alvo: str
    subdomains: Annotated[list[str], add]
    open_ports: Annotated[list[str], add]
    vulnerabilities: Annotated[list[dict], add]
    recon_ativo: Annotated[list[str], add]
    subfinder_vazio: bool
    fase_atual: str
    relatorio_final: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extrair_subdominios(texto: str, alvo: str) -> list[str]:
    linhas = [l.strip() for l in texto.splitlines() if l.strip()]
    padrao = re.compile(rf"[a-zA-Z0-9.\-]+\.{re.escape(alvo)}")
    return [l for l in linhas if padrao.search(l)]


def _extrair_portas(texto: str) -> list[str]:
    return re.findall(r"\d+/(?:tcp|udp)\s+open\s+\S+", texto)


def _extrair_vulns_nuclei(texto: str) -> list[dict]:
    vulns = []
    for match in re.finditer(
        r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[(critical|high|medium|low|info)\]',
        texto, re.IGNORECASE,
    ):
        template, proto, sev = match.groups()
        vulns.append({"template": template, "protocolo": proto, "severidade": sev})
    return vulns


def _invocar_seguro(invoke: Callable, prompt: str, config: dict) -> str:
    try:
        resultado = invoke({"messages": [("user", prompt)]}, config=config)
        return extrair_conteudo(resultado) or ""
    except Exception as e:
        msg = str(e)
        if "quota" in msg.lower() or "429" in msg:
            raise
        print(f"  {C.RED}[!] Erro: {msg}{C.RESET}")
        return ""


def _confirmar(fase_nome: str) -> bool:
    while True:
        try:
            r = input(
                f"\n{C.YELLOW}{C.BOLD}⚠  Fase '{fase_nome}' realiza operações agressivas. "
                f"Continuar? [s/n]: {C.RESET}"
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return False
        if r in ("s", "sim", "y", "yes"):
            return True
        if r in ("n", "nao", "não", "no"):
            return False


# ─── Nós do grafo ─────────────────────────────────────────────────────────────

def _node_subfinder(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"\n{C.CYAN}{C.BOLD}{_SEP}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  ▶  FASE 1/4 — RECONHECIMENTO PASSIVO{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP}{C.RESET}\n")
    print(f"  {C.GRAY}▷ subfinder em {alvo}{C.RESET}\n")

    conteudo = _invocar_seguro(
        invoke,
        f"Execute subfinder em {alvo} para enumerar subdomínios via fontes passivas",
        config,
    )
    subdominios = _extrair_subdominios(conteudo, alvo)
    vazio = len(subdominios) == 0

    if conteudo:
        print(formatar_para_terminal(conteudo))
    if vazio:
        print(f"  {C.YELLOW}[!] subfinder não encontrou subdomínios — ativando fallback DNS{C.RESET}\n")

    return {"subdomains": subdominios, "subfinder_vazio": vazio, "fase_atual": "recon_passivo"}


def _node_dns_bruteforce(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"  {C.YELLOW}▷ DNS brute-force (fallback) em {alvo}{C.RESET}\n")

    conteudo = _invocar_seguro(
        invoke,
        (
            f"Execute gobuster em modo DNS contra {alvo} para descobrir subdomínios "
            f"via brute-force. Use wordlist de subdomínios comuns. "
            f"Comando: gobuster dns -d {alvo} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -q"
        ),
        config,
    )
    subdominios = _extrair_subdominios(conteudo, alvo)
    if conteudo:
        print(formatar_para_terminal(conteudo))

    return {"subdomains": subdominios, "subfinder_vazio": False}


def _node_nmap(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"  {C.GRAY}▷ nmap em {alvo}{C.RESET}")
    conteudo = _invocar_seguro(
        invoke,
        f"Execute nmap em {alvo} com detecção de versão de serviços nas portas mais comuns",
        config,
    )
    portas = _extrair_portas(conteudo)
    if conteudo:
        print(formatar_para_terminal(conteudo))
    return {"open_ports": portas, "recon_ativo": [conteudo] if conteudo else []}


def _node_whatweb(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"  {C.GRAY}▷ whatweb em {alvo}{C.RESET}")
    conteudo = _invocar_seguro(
        invoke,
        f"Execute whatweb em {alvo} para identificar o stack tecnológico completo",
        config,
    )
    if conteudo:
        print(formatar_para_terminal(conteudo))
    return {"recon_ativo": [conteudo] if conteudo else []}


def _node_headers(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"  {C.GRAY}▷ headers HTTP em {alvo}{C.RESET}")
    conteudo = _invocar_seguro(
        invoke,
        f"Analise os headers HTTP de {alvo} verificando conformidade OWASP",
        config,
    )
    if conteudo:
        print(formatar_para_terminal(conteudo))
    return {"recon_ativo": [conteudo] if conteudo else []}


def _node_enum(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"\n{C.YELLOW}{C.BOLD}{_SEP}{C.RESET}")
    print(f"{C.YELLOW}{C.BOLD}  ⚠  FASE 3/4 — ENUMERAÇÃO{C.RESET}")
    print(f"{C.YELLOW}{C.BOLD}{_SEP}{C.RESET}\n")

    for prompt in [
        f"Execute gobuster em {alvo} com wordlist common para enumerar diretórios e arquivos",
        f"Execute nikto em {alvo} para identificar CVEs e misconfigurações do servidor web",
    ]:
        print(f"  {C.GRAY}▷ {prompt}{C.RESET}\n")
        conteudo = _invocar_seguro(invoke, prompt, config)
        if conteudo:
            print(formatar_para_terminal(conteudo))

    return {"fase_atual": "enumeracao"}


def _node_nuclei(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"\n{C.YELLOW}{C.BOLD}{_SEP}{C.RESET}")
    print(f"{C.YELLOW}{C.BOLD}  ⚠  FASE 4/4 — ANÁLISE DE VULNERABILIDADES{C.RESET}")
    print(f"{C.YELLOW}{C.BOLD}{_SEP}{C.RESET}\n")
    print(f"  {C.GRAY}▷ nuclei em {alvo}{C.RESET}\n")

    conteudo = _invocar_seguro(
        invoke,
        f"Execute nuclei em {alvo} com tags cve,exposure,misconfiguration,default-login",
        config,
    )
    vulns = _extrair_vulns_nuclei(conteudo)
    if conteudo:
        print(formatar_para_terminal(conteudo))

    return {"vulnerabilities": vulns, "fase_atual": "vulnerabilidades"}


def _node_recon_ativo_cabecalho(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    print(f"\n{C.CYAN}{C.BOLD}{_SEP}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  ▶  FASE 2/4 — RECONHECIMENTO ATIVO{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  Port scan + fingerprinting + headers{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP}{C.RESET}\n")
    return {}


def _node_relatorio(state: dict, invoke: Callable, config: dict) -> dict:
    alvo = state["alvo"]
    subdomains = state.get("subdomains", [])
    ports = state.get("open_ports", [])
    vulns = state.get("vulnerabilities", [])

    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  RELATÓRIO CONSOLIDADO — {alvo.upper()}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")
    print(f"  {C.GRAY}▷ Gerando sumário executivo...{C.RESET}\n")

    prompt = (
        f"Com base em todos os scans realizados em {alvo} nesta sessão "
        f"(subdomínios: {subdomains[:15]}, portas: {ports[:20]}, vulns: {vulns[:15]}), "
        f"gere um sumário executivo com: "
        f"1) superfície de ataque mapeada, "
        f"2) vulnerabilidades ordenadas por severidade, "
        f"3) vetores de ataque mais críticos, "
        f"4) recomendações prioritárias de correção."
    )
    try:
        conteudo = _invocar_seguro(invoke, prompt, config)
    except Exception:
        conteudo = "Quota excedida — relatório não gerado."

    if conteudo:
        print(formatar_para_terminal(conteudo))

    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  Pipeline concluído — {alvo}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")

    return {"relatorio_final": conteudo}


# ─── Roteadores condicionais ──────────────────────────────────────────────────

def _route_apos_subfinder(state: dict) -> str:
    """Se subfinder não encontrou nada → fallback DNS brute-force."""
    return "dns_bruteforce" if state.get("subfinder_vazio", True) else "recon_ativo"


def _route_para_enum(state: dict) -> str:
    """Gate interativo antes da Fase 3 destrutiva."""
    if _confirmar("Enumeração (Fase 3 — gobuster + nikto)"):
        return "enum"
    print(f"  {C.YELLOW}Fase 3 ignorada pelo usuário.{C.RESET}\n")
    return "gate_nuclei"


def _route_para_nuclei(state: dict) -> str:
    """Gate interativo antes da Fase 4 destrutiva."""
    if _confirmar("Análise de Vulnerabilidades (Fase 4 — nuclei)"):
        return "nuclei"
    print(f"  {C.YELLOW}Fase 4 ignorada pelo usuário.{C.RESET}\n")
    return "relatorio"


# ─── Builder ─────────────────────────────────────────────────────────────────

def construir_pipeline(invoke: Callable, config: dict):
    """
    Compila o StateGraph com fallback automático e checkpointing.

    Topologia:
      START → subfinder
              ↓ (vazio?)
              ├─ dns_bruteforce → recon_ativo
              └─ recon_ativo
                   ├─ nmap ┐
                   ├─ whatweb ┼─ (merge via add reducer) → gate_enum
                   └─ headers ┘
                        ↓ (confirmar?)
                        ├─ enum → gate_nuclei
                        └─ gate_nuclei
                              ↓ (confirmar?)
                              ├─ nuclei → relatorio
                              └─ relatorio → END
    """
    checkpointer = MemorySaver()
    graph = StateGraph(dict)

    # Registrar nós
    graph.add_node("subfinder",    lambda s: _node_subfinder(s, invoke, config))
    graph.add_node("dns_bruteforce", lambda s: _node_dns_bruteforce(s, invoke, config))
    graph.add_node("recon_ativo",  lambda s: _node_recon_ativo_cabecalho(s, invoke, config))
    graph.add_node("nmap",         lambda s: _node_nmap(s, invoke, config))
    graph.add_node("whatweb",      lambda s: _node_whatweb(s, invoke, config))
    graph.add_node("headers",      lambda s: _node_headers(s, invoke, config))
    graph.add_node("gate_enum",    lambda s: s)  # nó barreira — aguarda nmap+whatweb+headers
    graph.add_node("enum",         lambda s: _node_enum(s, invoke, config))
    graph.add_node("gate_nuclei",  lambda s: s)  # nó barreira
    graph.add_node("nuclei",       lambda s: _node_nuclei(s, invoke, config))
    graph.add_node("relatorio",    lambda s: _node_relatorio(s, invoke, config))

    # Arestas
    graph.add_edge(START, "subfinder")

    graph.add_conditional_edges(
        "subfinder",
        _route_apos_subfinder,
        {"dns_bruteforce": "dns_bruteforce", "recon_ativo": "recon_ativo"},
    )
    graph.add_edge("dns_bruteforce", "recon_ativo")

    # Fase 2: recon_ativo dispara nmap, whatweb, headers em sequência
    # (para paralelismo real use Send() com langgraph >= 0.2)
    graph.add_edge("recon_ativo", "nmap")
    graph.add_edge("recon_ativo", "whatweb")
    graph.add_edge("recon_ativo", "headers")
    graph.add_edge("nmap",    "gate_enum")
    graph.add_edge("whatweb", "gate_enum")
    graph.add_edge("headers", "gate_enum")

    graph.add_conditional_edges(
        "gate_enum",
        _route_para_enum,
        {"enum": "enum", "gate_nuclei": "gate_nuclei"},
    )
    graph.add_edge("enum", "gate_nuclei")

    graph.add_conditional_edges(
        "gate_nuclei",
        _route_para_nuclei,
        {"nuclei": "nuclei", "relatorio": "relatorio"},
    )
    graph.add_edge("nuclei",   "relatorio")
    graph.add_edge("relatorio", END)

    return graph.compile(checkpointer=checkpointer)


# ─── Compatibilidade com agente.py ────────────────────────────────────────────

def executar_pipeline_graph(alvo: str, invoke: Callable, config: dict) -> None:
    """
    Ponto de entrada compatível com a assinatura de pipeline.executar_pipeline().
    Substitua a chamada existente em agente.py por esta função.
    """
    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  PIPELINE GRAPH — {alvo.upper()}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  4 fases | fallback DNS | gate de confirmação{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")

    pipeline = construir_pipeline(invoke, config)
    estado_inicial = {
        "alvo": alvo,
        "subdomains": [],
        "open_ports": [],
        "vulnerabilities": [],
        "recon_ativo": [],
        "subfinder_vazio": False,
        "fase_atual": "inicio",
        "relatorio_final": "",
    }

    try:
        pipeline.invoke(estado_inicial, config=config)
    except Exception as e:
        msg = str(e)
        if "quota" in msg.lower() or "429" in msg:
            print(f"\n{C.RED}[!] Quota da API excedida — pipeline interrompido.{C.RESET}\n")
        else:
            print(f"\n{C.RED}[!] Erro no pipeline: {msg}{C.RESET}\n")
