import os
import time
import requests
import urllib3
from langchain_core.tools import tool
from security import validar_alvo, guardrail_check
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
from terminal import truncar_inteligente
import storage

OWASP_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

_MAX_CHARS = 3000


@tool
def analisar_headers(
    alvo: str,
    protocolo: str = "https",
    porta: int = 0,
    ignorar_ssl: bool = False,
    perfil_navegador: str = "",
    seguir_redirect: bool = True,
    metodo: str = "GET",
    forcar_novo: bool = False,
) -> str:
    """Coleta headers HTTP e verifica conformidade OWASP.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        protocolo: "https" (padrão) ou "http"
        porta: porta customizada (0 = padrão do protocolo: 80 ou 443)
        ignorar_ssl: ignorar erros de certificado SSL — use para certs autoassinados
        perfil_navegador: simular navegador — chrome, firefox, safari, googlebot
        seguir_redirect: seguir redirecionamentos HTTP (padrão True)
        metodo: "GET" (padrão) ou "HEAD" — HEAD é mais rápido, só retorna headers
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    protocolo = protocolo.lower()
    if protocolo not in ("http", "https"):
        return "Erro: protocolo deve ser 'http' ou 'https'."

    metodo = metodo.upper()
    if metodo not in ("GET", "HEAD"):
        return "Erro: método deve ser 'GET' ou 'HEAD'."

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    chave_porta = str(porta) if porta else ""

    try:
        guardrail_check("headers", alvo_limpo, f"{protocolo}://{alvo_limpo}")
    except PermissionError as e:
        return str(e)

    if not forcar_novo:
        if ja_executado(alvo_limpo, "headers", protocolo, chave_porta, str(ignorar_ssl), perfil_navegador):
            return "Análise de headers já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "headers", horas=12)
        if cache:
            registrar(alvo_limpo, "headers", protocolo, chave_porta, str(ignorar_ssl), perfil_navegador)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{truncar_inteligente(cache['resultado'], _MAX_CHARS)}"

    registrar(alvo_limpo, "headers", protocolo, chave_porta, str(ignorar_ssl), perfil_navegador)

    if ignorar_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    req_headers = {}
    if perfil:
        req_headers["User-Agent"] = perfil["ua"]
        req_headers.update(perfil["headers"])

    url = f"{protocolo}://{alvo_limpo}"
    if porta:
        url += f":{porta}"

    inicio = time.time()
    try:
        fn = requests.head if metodo == "HEAD" else requests.get
        response = fn(
            url,
            timeout=15,
            verify=not ignorar_ssl,
            headers=req_headers or None,
            allow_redirects=seguir_redirect,
        )
        duracao_ms = int((time.time() - inicio) * 1000)
        headers = response.headers
        raw = "\n".join(f"{k}: {v}" for k, v in headers.items())

        faltantes = [h for h in OWASP_HEADERS if h.lower() not in {k.lower() for k in headers.keys()}]

        saida = (
            f"ALVO: {url} [{response.status_code}]\n\n"
            f"HEADERS ENCONTRADOS:\n{raw}\n\n"
            f"OWASP FALTANDO: {', '.join(faltantes) if faltantes else 'Nenhum ✅'}"
        )
        storage.salvar(alvo_limpo, "headers", saida, {"protocolo": protocolo, "porta": porta, "perfil": perfil_navegador})
        storage.salvar_metrica("headers", alvo_limpo, response.status_code, duracao_ms, True)
        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW headers]\n{saida}\n[/RAW]\n")
        return truncar_inteligente(saida, _MAX_CHARS)
    except requests.exceptions.SSLError:
        duracao_ms = int((time.time() - inicio) * 1000)
        storage.salvar_metrica("headers", alvo_limpo, -1, duracao_ms, False)
        return (
            "Erro SSL: certificado inválido ou autoassinado.\n"
            "Dica de correção: use ignorar_ssl=True para ignorar verificação de certificado."
        )
    except requests.exceptions.ConnectionError:
        duracao_ms = int((time.time() - inicio) * 1000)
        storage.salvar_metrica("headers", alvo_limpo, -1, duracao_ms, False)
        return (
            f"Erro de conexão com {url}.\n"
            "Dica de correção: verifique se o alvo está acessível. "
            "Tente protocolo='http' se o alvo não suporta HTTPS."
        )
    except Exception as e:
        duracao_ms = int((time.time() - inicio) * 1000)
        storage.salvar_metrica("headers", alvo_limpo, -1, duracao_ms, False)
        return str(e)
