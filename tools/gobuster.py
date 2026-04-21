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

EXTENSOES_VALIDAS = re.compile(r"^[a-zA-Z0-9,]{1,50}$")


@tool
def executar_gobuster(
    alvo: str,
    wordlist: str = "common",
    extensoes: str = "",
    perfil_navegador: str = "",
    delay: str = "",
    threads: int = 20,
) -> str:
    """Enumera diretórios e arquivos ocultos no alvo com Gobuster.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        wordlist: "small" (~950), "common" (padrão, ~4700), "medium" (~30k), "big" (~62k)
        extensoes: extensões a buscar separadas por vírgula (ex: "php,html,txt")
        perfil_navegador: simular navegador real para contornar WAF — perfis: chrome, firefox, safari, googlebot
        delay: pausa entre requisições para evitar rate limit (ex: "500ms", "1s", "2s")
        threads: número de threads paralelas (padrão 20, mín 1, máx 50)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    threads = max(1, min(50, int(threads)))

    if delay and not re.match(r"^\d+(ms|s)$", delay):
        return "Erro: delay inválido. Use formato como '500ms' ou '2s'."

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if ja_executado(alvo_limpo, "gobuster", wordlist, extensoes, perfil_navegador):
        return "Enumeração gobuster já realizada para este alvo nesta sessão. Use o resultado anterior disponível no contexto ou consulte agente_historico."

    registrar(alvo_limpo, "gobuster", wordlist, extensoes, perfil_navegador)

    caminho_wordlist = WORDLISTS_PERMITIDAS.get(wordlist, WORDLISTS_PERMITIDAS["common"])
    url = f"https://{alvo_limpo}"

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

    if extensoes and EXTENSOES_VALIDAS.match(extensoes):
        comando += ["-x", extensoes]

    if perfil:
        comando += ["-a", perfil["ua"]]
        for chave, valor in perfil["headers"].items():
            comando += ["-H", f"{chave}: {valor}"]

    if delay:
        comando += ["--delay", delay]

    print(f"[gobuster] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
        saida = resultado.stdout.strip() or "Nenhum diretório encontrado com esta wordlist."
        storage.salvar(alvo_limpo, "gobuster", saida, {"wordlist": wordlist, "extensoes": extensoes, "perfil": perfil_navegador})
        return saida
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (300s). Tente uma wordlist menor ou mais threads."
    except FileNotFoundError:
        return "Erro: gobuster não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
