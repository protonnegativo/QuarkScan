from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from agents.base import extrair_conteudo
from terminal import C, formatar_para_terminal

_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
_DOM = r"[a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
_ALVO = rf"({_DOM}|{_IP})"

_PADROES_PIPELINE = [
    rf"pipeline\s+(?:em\s+)?{_ALVO}",
    rf"modo\s+aut[oô]nomo\s+(?:em\s+)?{_ALVO}",
    rf"pentest\s+completo\s+(?:em\s+)?{_ALVO}",
]


@dataclass
class _Fase:
    numero: int
    nome: str
    descricao: str
    prompts: list[str]
    destrutiva: bool = False


_FASES: list[_Fase] = [
    _Fase(
        numero=1,
        nome="Reconhecimento Passivo",
        descricao="Enumeração de subdomínios via fontes passivas",
        prompts=[
            "Execute subfinder em {alvo} para enumerar subdomínios via fontes passivas",
        ],
    ),
    _Fase(
        numero=2,
        nome="Reconhecimento Ativo",
        descricao="Port scan, fingerprinting de stack e análise de headers",
        prompts=[
            "Execute nmap em {alvo} com detecção de versão de serviços nas portas mais comuns",
            "Execute whatweb em {alvo} para identificar o stack tecnológico completo",
            "Analise os headers HTTP de {alvo} verificando conformidade OWASP",
        ],
    ),
    _Fase(
        numero=3,
        nome="Enumeração",
        descricao="Diretórios ocultos e vulnerabilidades de servidor",
        prompts=[
            "Execute gobuster em {alvo} com wordlist common para enumerar diretórios e arquivos",
            "Execute nikto em {alvo} para identificar CVEs e misconfigurações do servidor web",
        ],
        destrutiva=True,
    ),
    _Fase(
        numero=4,
        nome="Análise de Vulnerabilidades",
        descricao="Varredura por CVEs, exposições e defaults de login",
        prompts=[
            "Execute nuclei em {alvo} com tags cve,exposure,misconfiguration,default-login",
        ],
        destrutiva=True,
    ),
]

_SEP = chr(9472) * 60
_SEP2 = chr(9552) * 60


def detectar_alvo_pipeline(texto: str) -> Optional[str]:
    for padrao in _PADROES_PIPELINE:
        m = re.search(padrao, texto, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _cabecalho_fase(fase: _Fase) -> str:
    cor = C.YELLOW if fase.destrutiva else C.CYAN
    icone = "⚠" if fase.destrutiva else "▶"
    return (
        f"\n{cor}{C.BOLD}{_SEP}\n"
        f"  {icone}  FASE {fase.numero}/{len(_FASES)} — {fase.nome.upper()}\n"
        f"  {fase.descricao}\n"
        f"{_SEP}{C.RESET}\n"
    )


def _confirmar_fase(fase: _Fase) -> bool:
    while True:
        try:
            r = input(
                f"\n{C.YELLOW}{C.BOLD}⚠  Fase {fase.numero} ({fase.nome}) realiza "
                f"operações mais agressivas no alvo.\n"
                f"   Continuar? [s/n]: {C.RESET}"
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return False
        if r in ("s", "sim", "y", "yes"):
            return True
        if r in ("n", "nao", "não", "no"):
            return False


def _invocar(invoke: Callable, prompt: str, config: dict) -> Optional[str]:
    try:
        resultado = invoke({"messages": [("user", prompt)]}, config=config)
        return extrair_conteudo(resultado)
    except Exception as e:
        msg = str(e)
        if "quota" in msg.lower() or "429" in msg:
            raise
        print(f"  {C.RED}[!] Erro: {msg}{C.RESET}\n")
        return None


def executar_pipeline(alvo: str, invoke: Callable, config: dict) -> None:
    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  PIPELINE — {alvo.upper()}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  {len(_FASES)} fases | confirmação antes de fases destrutivas{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")

    for fase in _FASES:
        if fase.destrutiva and not _confirmar_fase(fase):
            print(f"  {C.YELLOW}Fase {fase.numero} ignorada pelo usuário.{C.RESET}\n")
            continue

        print(_cabecalho_fase(fase))

        for prompt_template in fase.prompts:
            prompt = prompt_template.format(alvo=alvo)
            print(f"  {C.GRAY}▷ {prompt}{C.RESET}\n")
            try:
                conteudo = _invocar(invoke, prompt, config)
            except Exception:
                print(f"  {C.RED}[!] Quota da API excedida — pipeline interrompido.{C.RESET}\n")
                return
            if conteudo:
                print(formatar_para_terminal(conteudo))

    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  RELATÓRIO CONSOLIDADO — {alvo.upper()}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")
    print(f"  {C.GRAY}▷ Gerando sumário executivo...{C.RESET}\n")

    prompt_relatorio = (
        f"Com base em todos os scans realizados em {alvo} nesta sessão, "
        f"gere um sumário executivo com: "
        f"1) superfície de ataque mapeada (subdomínios, portas abertas, stack tecnológico), "
        f"2) vulnerabilidades encontradas ordenadas por severidade, "
        f"3) vetores de ataque mais críticos identificados, "
        f"4) recomendações prioritárias de correção."
    )
    try:
        conteudo = _invocar(invoke, prompt_relatorio, config)
    except Exception:
        print(f"  {C.RED}[!] Quota da API excedida — relatório não gerado.{C.RESET}\n")
        conteudo = None
    if conteudo:
        print(formatar_para_terminal(conteudo))

    print(f"\n{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  Pipeline concluído — {alvo}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{_SEP2}{C.RESET}\n")
