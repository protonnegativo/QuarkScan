import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage

_MAX_CHARS = 6000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_nikto(
    alvo: str,
    porta: str = "443",
    ssl: bool = True,
    perfil_navegador: str = "",
    evasao: str = "",
    pausa: int = 0,
    raiz: str = "",
    vhost: str = "",
    plugins: str = "",
    forcar_novo: bool = False,
) -> str:
    """Executa varredura de vulnerabilidades web com Nikto.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        porta: porta alvo (padrão 443)
        ssl: usar SSL/TLS (padrão True)
        perfil_navegador: simular navegador — chrome, firefox, safari, googlebot
        evasao: técnicas IDS/WAF separadas por vírgula (ex: "1,2,6")
                1=maiúsculas aleatórias  2=adiciona barra  3=URL encode
                5=fake parâmetro  6=TAB  8=aleatório
        pausa: segundos entre requisições (0=sem pausa, máx 60)
        raiz: prefixo de path para todos os testes (ex: "/app", "/api/v1")
        vhost: virtual host alternativo para testar (ex: "admin.exemplo.com")
        plugins: plugins específicos a executar (ex: "headers,robots")
                 Use "ALL" para todos. Padrão: todos os relevantes.
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    if not re.match(r"^\d{1,5}$", porta) or not (1 <= int(porta) <= 65535):
        return "Erro: porta inválida."

    if pausa < 0 or pausa > 60:
        return "Erro: pausa deve estar entre 0 e 60."

    if raiz and not re.match(r"^/[a-zA-Z0-9/\-_.]*$", raiz):
        return "Erro: raiz inválida. Use formato como '/api' ou '/app/v2'."

    if vhost and not re.match(r"^[a-zA-Z0-9.\-]+$", vhost):
        return "Erro: vhost inválido."

    if not forcar_novo:
        if ja_executado(alvo_limpo, "nikto", porta, str(ssl), evasao, raiz):
            return "Scan nikto já realizado com esses parâmetros nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "nikto", horas=24)
        if cache:
            registrar(alvo_limpo, "nikto", porta, str(ssl), evasao, raiz)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "nikto", porta, str(ssl), evasao, raiz)

    comando = [
        "nikto",
        "-h", alvo_limpo,
        "-p", porta,
        "-nointeractive",
        "-maxtime", "300s",
    ]

    if ssl:
        comando.append("-ssl")

    perfil = obter_perfil(perfil_navegador)
    if perfil:
        comando += ["-useragent", perfil["ua"]]
    elif perfil_navegador:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if evasao and re.match(r"^[1-8](,[1-8])*$", evasao):
        comando += ["-evasion", evasao.replace(",", "")]

    if pausa > 0:
        comando += ["-pause", str(pausa)]

    if raiz:
        comando += ["-root", raiz]

    if vhost:
        comando += ["-vhost", vhost]

    if plugins:
        comando += ["-Plugins", plugins]

    print(f"[nikto] Executando: {' '.join(comando)}")

    timeout = 360
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        saida = resultado.stdout.strip() or resultado.stderr or "Nikto não retornou resultados."
        storage.salvar(alvo_limpo, "nikto", saida, {
            "porta": porta, "ssl": ssl, "perfil": perfil_navegador,
            "evasao": evasao, "raiz": raiz, "vhost": vhost,
        })
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return f"Erro: timeout ({timeout}s)."
    except FileNotFoundError:
        return "Erro: nikto não encontrado."
    except Exception as e:
        return str(e)
