import subprocess
from langchain_core.tools import tool
from security import validar_alvo

WORDLISTS_PERMITIDAS = {
    "common":   "/usr/share/dirb/wordlists/common.txt",
    "small":    "/usr/share/dirb/wordlists/small.txt",
    "big":      "/usr/share/dirb/wordlists/big.txt",
    "medium":   "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
}

EXTENSOES_VALIDAS = re.compile(r"^[a-zA-Z0-9,]{1,50}$")

import re


@tool
def executar_gobuster(alvo: str, wordlist: str = "common", extensoes: str = "") -> str:
    """Enumera diretórios e arquivos ocultos no alvo com Gobuster.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        wordlist: tamanho da wordlist — "common" (padrão), "small", "big", "medium"
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
