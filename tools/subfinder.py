import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from session import ja_executado, registrar
import storage

_KEYWORDS_INTERESSE = {
    "api", "admin", "dev", "staging", "jenkins", "portal", "vpn", "git",
    "ci", "monitor", "test", "uat", "app", "backend", "internal", "mgmt",
    "manage", "console", "dashboard", "login", "auth", "mail", "smtp",
    "ftp", "bastion", "proxy", "artifactory", "sonar", "jira", "confluence",
}


def _prioritarios(saida: str) -> str:
    linhas = [l.strip() for l in saida.splitlines() if l.strip()]
    encontrados = [
        sub for sub in linhas
        if any(kw in sub.split(".")[0].lower() for kw in _KEYWORDS_INTERESSE)
    ]
    if not encontrados:
        return ""
    return "\n\n## SUBDOMÍNIOS_PRIORITÁRIOS\n" + "\n".join(encontrados[:30])


@tool
def executar_subfinder(
    alvo: str,
    recursivo: bool = False,
    todas_fontes: bool = False,
) -> str:
    """Enumera subdomínios do alvo via reconhecimento passivo com subfinder.

    Args:
        alvo: domínio alvo (ex: exemplo.com)
        recursivo: enumerar subdomínios dos subdomínios encontrados (mais lento, mais completo)
        todas_fontes: usar todas as fontes disponíveis — mais resultados, mais lento
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use um domínio válido."

    if ja_executado(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes)):
        return "Enumeração subfinder já realizada para este alvo nesta sessão. Use o resultado anterior disponível no contexto ou consulte agente_historico."

    registrar(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes))

    comando = [
        "subfinder",
        "-d", alvo_limpo,
        "-silent",
        "-timeout", "30",
    ]

    if recursivo:
        comando.append("-recursive")

    if todas_fontes:
        comando.append("-all")

    print(f"[subfinder] Executando: {' '.join(comando)}")

    timeout = 240 if recursivo or todas_fontes else 120
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        saida = resultado.stdout.strip() or "Nenhum subdomínio encontrado."
        if resultado.stdout.strip():
            saida += _prioritarios(saida)
        storage.salvar(alvo_limpo, "subfinder", saida, {"recursivo": recursivo, "todas_fontes": todas_fontes})
        return saida
    except subprocess.TimeoutExpired:
        return f"Erro: timeout atingido ({timeout}s)."
    except FileNotFoundError:
        return "Erro: subfinder não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
