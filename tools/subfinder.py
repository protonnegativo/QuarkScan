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

_MAX_CHARS = 8000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    linhas = texto.splitlines()
    resultado = []
    chars = 0
    for linha in linhas:
        if chars + len(linha) > _MAX_CHARS:
            resultado.append(f"... [{len(linhas)} subdomínios total — exibindo primeiros {len(resultado)}]")
            break
        resultado.append(linha)
        chars += len(linha) + 1
    return "\n".join(resultado)


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
    threads: int = 10,
    max_tempo: int = 0,
    sem_wildcards: bool = True,
    forcar_novo: bool = False,
) -> str:
    """Enumera subdomínios via reconhecimento passivo com subfinder.

    Args:
        alvo: domínio alvo (ex: exemplo.com)
        recursivo: enumerar subdomínios dos subdomínios encontrados
                   (mais lento e completo — recomendado para varredura profunda)
        todas_fontes: usar todas as fontes disponíveis (mais resultados, mais lento)
        threads: goroutines paralelas por fonte (padrão 10, máx 50)
        max_tempo: tempo máximo em minutos (0 = sem limite)
                   use 5-10 para scans rápidos, 0 para varredura completa
        sem_wildcards: filtrar subdomínios wildcard do resultado (padrão True)
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use um domínio válido."

    threads = max(1, min(50, int(threads)))

    if not forcar_novo:
        if ja_executado(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes)):
            return "Enumeração subfinder já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "subfinder", horas=72)
        if cache:
            registrar(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes))
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes))

    comando = [
        "subfinder",
        "-d", alvo_limpo,
        "-silent",
        "-timeout", "30",
        "-t", str(threads),
    ]

    if recursivo:
        comando.append("-recursive")

    if todas_fontes:
        comando.append("-all")

    if max_tempo > 0:
        comando += ["-max-time", str(max_tempo)]

    if sem_wildcards:
        comando.append("-nW")

    print(f"[subfinder] Executando: {' '.join(comando)}")

    timeout = 240 if recursivo or todas_fontes else 120
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        saida_bruta = resultado.stdout.strip()
        if not saida_bruta:
            return "Nenhum subdomínio encontrado."
        prioritarios = _prioritarios(saida_bruta)
        saida_completa = saida_bruta + prioritarios
        storage.salvar(alvo_limpo, "subfinder", saida_completa, {
            "recursivo": recursivo, "todas_fontes": todas_fontes,
        })
        return _truncar(saida_bruta) + prioritarios
    except subprocess.TimeoutExpired:
        return f"Erro: timeout ({timeout}s)."
    except FileNotFoundError:
        return "Erro: subfinder não encontrado."
    except Exception as e:
        return str(e)
