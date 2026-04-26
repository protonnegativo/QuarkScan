import os
import subprocess
from langchain_core.tools import tool
from security import validar_alvo, guardrail_check
from session import ja_executado, registrar
from terminal import executar_com_monitoramento, truncar_inteligente
import storage

_KEYWORDS_INTERESSE = {
    "api", "admin", "dev", "staging", "jenkins", "portal", "vpn", "git",
    "ci", "monitor", "test", "uat", "app", "backend", "internal", "mgmt",
    "manage", "console", "dashboard", "login", "auth", "mail", "smtp",
    "ftp", "bastion", "proxy", "artifactory", "sonar", "jira", "confluence",
}

_MAX_CHARS = 8000


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

    try:
        guardrail_check("subfinder", alvo_limpo, f"-d {alvo_limpo} -t {threads}")
    except PermissionError as e:
        return str(e)

    if not forcar_novo:
        if ja_executado(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes)):
            return "Enumeração subfinder já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "subfinder", horas=72)
        if cache:
            registrar(alvo_limpo, "subfinder", str(recursivo), str(todas_fontes))
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{truncar_inteligente(cache['resultado'], _MAX_CHARS)}"

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
        res = executar_com_monitoramento(comando, timeout=timeout, ferramenta="subfinder", alvo=alvo_limpo)
        saida_bruta = res.stdout.strip()
        if not saida_bruta and not res.sucesso:
            return res.erro_autocorrecao(
                "verifique conexão com a internet e se o domínio existe. "
                "Para domínios internos, tente todas_fontes=False e sem_wildcards=False"
            )
        if not saida_bruta:
            storage.salvar_metrica("subfinder", alvo_limpo, res.exit_code, res.duracao_ms, True)
            return "Nenhum subdomínio encontrado."
        prioritarios = _prioritarios(saida_bruta)
        saida_completa = saida_bruta + prioritarios
        storage.salvar(alvo_limpo, "subfinder", saida_completa, {
            "recursivo": recursivo, "todas_fontes": todas_fontes,
        }, raw_output=saida_bruta)
        storage.salvar_metrica("subfinder", alvo_limpo, res.exit_code, res.duracao_ms, res.sucesso)
        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW subfinder]\n{saida_completa}\n[/RAW]\n")
        # Truncation preserves the tail (SUBDOMÍNIOS_PRIORITÁRIOS section)
        linhas = saida_bruta.splitlines()
        resultado_linhas = []
        chars = 0
        for linha in linhas:
            if chars + len(linha) > _MAX_CHARS:
                resultado_linhas.append(f"... [{len(linhas)} subdomínios total — exibindo primeiros {len(resultado_linhas)}]")
                break
            resultado_linhas.append(linha)
            chars += len(linha) + 1
        return "\n".join(resultado_linhas) + prioritarios
    except subprocess.TimeoutExpired:
        return f"Erro: timeout ({timeout}s). Use max_tempo=5 para limitar a varredura."
    except FileNotFoundError:
        return "Erro: subfinder não encontrado."
    except Exception as e:
        return str(e)
