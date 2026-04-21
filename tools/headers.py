import requests
import urllib3
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage

OWASP_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


@tool
def analisar_headers(
    alvo: str,
    ignorar_ssl: bool = False,
    perfil_navegador: str = "",
) -> str:
    """Coleta todos os headers HTTP e verifica faltantes conforme OWASP.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        ignorar_ssl: ignorar erros de certificado SSL — use True apenas para certs inválidos/autoassinados
        perfil_navegador: simular navegador real — perfis: chrome, firefox, safari, googlebot
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if ja_executado(alvo_limpo, "headers", str(ignorar_ssl), perfil_navegador):
        return "Análise de headers já realizada para este alvo nesta sessão. Use o resultado anterior disponível no contexto ou consulte agente_historico."

    registrar(alvo_limpo, "headers", str(ignorar_ssl), perfil_navegador)

    if ignorar_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    req_headers = {}
    if perfil:
        req_headers["User-Agent"] = perfil["ua"]
        req_headers.update(perfil["headers"])

    url = f"https://{alvo_limpo}"
    try:
        response = requests.get(url, timeout=15, verify=not ignorar_ssl, headers=req_headers or None)
        headers = response.headers
        raw = "\n".join([f"{k}: {v}" for k, v in headers.items()])

        faltantes = [h for h in OWASP_HEADERS if h.lower() not in [k.lower() for k in headers.keys()]]

        saida = (
            f"ALVO: {url}\n\n"
            f"HEADERS ENCONTRADOS:\n{raw}\n\n"
            f"AVISO: Headers OWASP faltando: {', '.join(faltantes) if faltantes else 'Nenhum ✅'}"
        )
        storage.salvar(alvo_limpo, "headers", saida, {"perfil": perfil_navegador})
        return saida
    except Exception as e:
        return str(e)
