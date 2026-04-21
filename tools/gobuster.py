import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage

WORDLISTS_PERMITIDAS = {
    "small":  "/usr/share/dirb/wordlists/small.txt",
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "big":    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
}

_EXTENSOES_RE = re.compile(r"^[a-zA-Z0-9,]{1,50}$")
_STATUS_RE = re.compile(r"^[\d,]+$")
_MAX_CHARS = 5000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_gobuster(
    alvo: str,
    protocolo: str = "https",
    wordlist: str = "common",
    extensoes: str = "",
    perfil_navegador: str = "",
    delay: str = "",
    threads: int = 20,
    status_codes: str = "",
    excluir_status: str = "",
    excluir_comprimento: str = "",
    seguir_redirect: bool = False,
    forcar_novo: bool = False,
) -> str:
    """Enumera diretórios e arquivos ocultos com Gobuster.

    Args:
        alvo: domínio ou IP (ex: exemplo.com)
        protocolo: "https" (padrão) ou "http"
        wordlist: "small" (~950), "common" (padrão ~4700), "medium" (~30k), "big" (~62k)
        extensoes: extensões separadas por vírgula (ex: "php,html,txt,bak")
                   PHP: php,html,txt,bak | Java: jsp,do,action | .NET: asp,aspx,config
        perfil_navegador: chrome, firefox, safari, googlebot
        delay: pausa entre requisições — "500ms", "1s", "2s"
        threads: paralelismo (padrão 20, mín 1, máx 50)
        status_codes: whitelist de status codes a exibir (ex: "200,301,302,401,403")
        excluir_status: blacklist de status codes a ignorar (ex: "404,429,503")
        excluir_comprimento: excluir respostas por tamanho em bytes (ex: "0,1234")
                             útil para ignorar respostas wildcard
        seguir_redirect: seguir redirecionamentos (padrão False)
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    protocolo = protocolo.lower()
    if protocolo not in ("http", "https"):
        return "Erro: protocolo deve ser 'http' ou 'https'."

    threads = max(1, min(50, int(threads)))

    if delay and not re.match(r"^\d+(ms|s)$", delay):
        return "Erro: delay inválido. Use formato como '500ms' ou '2s'."

    if status_codes and not _STATUS_RE.match(status_codes):
        return "Erro: status_codes inválido. Use somente números separados por vírgula."

    if excluir_status and not _STATUS_RE.match(excluir_status):
        return "Erro: excluir_status inválido. Use somente números separados por vírgula."

    if excluir_comprimento and not _STATUS_RE.match(excluir_comprimento):
        return "Erro: excluir_comprimento inválido. Use números separados por vírgula."

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if not forcar_novo:
        if ja_executado(alvo_limpo, "gobuster", wordlist, extensoes, perfil_navegador):
            return "Enumeração gobuster já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "gobuster", horas=48)
        if cache:
            registrar(alvo_limpo, "gobuster", wordlist, extensoes, perfil_navegador)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "gobuster", wordlist, extensoes, perfil_navegador)

    caminho_wordlist = WORDLISTS_PERMITIDAS.get(wordlist, WORDLISTS_PERMITIDAS["common"])
    url = f"{protocolo}://{alvo_limpo}"

    comando = [
        "gobuster", "dir",
        "-u", url,
        "-w", caminho_wordlist,
        "-q",
        "--no-error",
        "-t", str(threads),
        "--timeout", "10s",
        "-k",
    ]

    if extensoes and _EXTENSOES_RE.match(extensoes):
        comando += ["-x", extensoes]

    if perfil:
        comando += ["-a", perfil["ua"]]
        for chave, valor in perfil["headers"].items():
            comando += ["-H", f"{chave}: {valor}"]

    if delay:
        comando += ["--delay", delay]

    if status_codes:
        comando += ["-s", status_codes]

    if excluir_status:
        comando += ["-b", excluir_status]

    if excluir_comprimento:
        comando += ["--exclude-length", excluir_comprimento]

    if seguir_redirect:
        comando.append("-r")

    print(f"[gobuster] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
        saida = resultado.stdout.strip() or "Nenhum diretório encontrado com esta wordlist."
        storage.salvar(alvo_limpo, "gobuster", saida, {
            "wordlist": wordlist, "extensoes": extensoes, "perfil": perfil_navegador,
        })
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return "Erro: timeout (300s). Tente wordlist menor ou aumente threads."
    except FileNotFoundError:
        return "Erro: gobuster não encontrado."
    except Exception as e:
        return str(e)
