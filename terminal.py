import re
import subprocess
import time
import threading
from dataclasses import dataclass


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    GRAY    = "\033[90m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"


def formatar_para_terminal(texto: str) -> str:
    linhas = texto.split("\n")
    saida = []

    for linha in linhas:
        if linha.startswith("### "):
            titulo = linha[4:].strip()
            saida.append(f"\n{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}  {titulo}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")

        elif linha.strip().startswith("[CACHE "):
            data = linha.strip()
            saida.append(f"\n  {C.MAGENTA}{C.BOLD}⚡ {data}{C.RESET}")

        elif re.match(r"^\s*[\*\-] \*\*", linha):
            conteudo_l = re.sub(
                r"\*\*(.+?)\*\*",
                lambda m: f"{C.YELLOW}{C.BOLD}{m.group(1)}{C.RESET}",
                linha.strip().lstrip("*- "),
            )
            saida.append(f"\n  {C.YELLOW}{chr(9654)}{C.RESET} {conteudo_l}")

        elif re.match(r"^\s{2,}- \*\*", linha):
            label = re.search(r"\*\*(.+?)\*\*", linha)
            resto = re.sub(r"\*\*(.+?)\*\*[:\s]*", "", linha).strip().lstrip("- ")
            if label:
                chave = label.group(1)
                if any(w in chave for w in ["Risco", "CVE", "Vuln", "Severidade"]):
                    cor = C.RED
                elif any(w in chave for w in ["Mitiga", "Melhoria", "Configura", "serve", "Recomenda", "Correção"]):
                    cor = C.GREEN
                else:
                    cor = C.WHITE
                saida.append(f"      {cor}{C.BOLD}{chave}:{C.RESET} {resto}")

        elif "**" in linha:
            limpo = re.sub(
                r"\*\*(.+?)\*\*",
                lambda m: f"{C.BOLD}{m.group(1)}{C.RESET}",
                linha,
            )
            saida.append(f"  {limpo}")

        elif "`" in linha:
            limpo = re.sub(r"`(.+?)`", lambda m: f"{C.GRAY}{m.group(1)}{C.RESET}", linha)
            saida.append(f"  {limpo}")

        elif re.match(r"^\s*\+\s", linha):
            saida.append(f"  {C.GREEN}{linha}{C.RESET}")
        elif re.match(r"^\s*-\s", linha):
            saida.append(f"  {C.RED}{linha}{C.RESET}")

        elif linha.strip() == "":
            saida.append("")

        else:
            saida.append(f"  {linha}")

    return "\n".join(saida)


# ─── Execução com Monitoramento ───────────────────────────────────────────────

@dataclass
class ResultadoExecucao:
    """Encapsula stdout, stderr, exit_code e métricas de execução de uma ferramenta."""
    stdout: str
    stderr: str
    exit_code: int
    duracao_ms: int
    ferramenta: str
    alvo: str

    @property
    def sucesso(self) -> bool:
        return self.exit_code == 0

    def saida_principal(self) -> str:
        """Retorna stdout se houver, senão stderr."""
        return self.stdout.strip() or self.stderr.strip()

    def erro_autocorrecao(self, dica: str = "") -> str:
        """Formata mensagem de erro acionável para que o agente se autocorrija."""
        msg = f"Erro de execução (código {self.exit_code})."
        stderr = self.stderr.strip()
        if stderr:
            msg += f"\nDetalhe: {stderr[:400]}"
        if dica:
            msg += f"\nDica de correção: {dica}"
        return msg


def executar_com_monitoramento(
    comando: list,
    timeout: int,
    ferramenta: str,
    alvo: str,
    heartbeat_interval: int = 30,
) -> ResultadoExecucao:
    """Executa um comando externo com heartbeat de progresso e captura de métricas.

    Imprime atualizações periódicas para que o usuário saiba que a ferramenta está
    ativa em execuções longas (nmap -p-, nuclei, etc.).
    Eleva TimeoutExpired / FileNotFoundError normalmente — o caller trata.
    """
    inicio = time.time()
    _ativo = [True]

    def _heartbeat():
        while _ativo[0]:
            elapsed = int(time.time() - inicio)
            print(f"  [{ferramenta}] {elapsed}s/{timeout}s — em execução...", flush=True)
            time.sleep(heartbeat_interval)

    t = threading.Thread(target=_heartbeat, daemon=True)
    t.start()

    try:
        proc = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        duracao_ms = int((time.time() - inicio) * 1000)
        return ResultadoExecucao(
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duracao_ms=duracao_ms,
            ferramenta=ferramenta,
            alvo=alvo,
        )
    finally:
        _ativo[0] = False


def truncar_inteligente(texto: str, max_chars: int) -> str:
    """Mantém início (contexto) + fim (achados/conclusões), descartando o meio.

    Estratégia 65/35: a maioria das ferramentas ofensivas imprime achados ao final.
    """
    if len(texto) <= max_chars:
        return texto
    cabeca = int(max_chars * 0.65)
    cauda = int(max_chars * 0.35)
    omitidos = len(texto) - cabeca - cauda
    return (
        texto[:cabeca]
        + f"\n\n... [{omitidos} chars omitidos — {len(texto)} total] ...\n\n"
        + texto[-cauda:]
    )
