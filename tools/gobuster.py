import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo

WORDLISTS_PERMITIDAS = {
    "small":  "/usr/share/dirb/wordlists/small.txt",
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "big":    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
}

EXTENSOES_VALIDAS = re.compile(r"^[a-zA-Z0-9,]{1,50}$")


@tool
def executar_gobuster(alvo: str, wordlist: str = "common", extensoes: str = "") -> str:
    """Enumera diretórios e arquivos ocultos no alvo com Gobuster.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        wordlist: wordlist — "small" (~950), "common" (padrão, ~4700 SecLists), "medium" (~30k SecLists), "big" (~62k SecLists)
        extensoes: extensões a buscar separadas por vírgula (ex: "php,html,txt")
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    caminho_wordlist = WORDLISTS_PERMITIDAS.get(wordlist, WORDLISTS_PERMITIDAS["common"])
    url = f"https://{alvo_limpo}"

    comando = [
        "gobuster", "dir",
        "-u", url,
        "-w", caminho_wordlist,
        "-q",
        "--no-error",
        "-t", "20",
        "--timeout", "10s",
        "-k",
    ]

    if extensoes and EXTENSOES_VALIDAS.match(extensoes):
        comando += ["-x", extensoes]

    print(f"[gobuster] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
        saida = resultado.stdout.strip()
        return saida if saida else "Nenhum diretório encontrado com esta wordlist."
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (300s). Tente uma wordlist menor."
    except FileNotFoundError:
        return "Erro: gobuster não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
