import requests
import urllib3
from langchain_core.tools import tool
from security import validar_alvo
import storage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OWASP_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


@tool
def analisar_headers(alvo: str) -> str:
    """Coleta todos os headers HTTP e verifica faltantes conforme OWASP."""
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    url = f"https://{alvo_limpo}"
    try:
        response = requests.get(url, timeout=15, verify=False)
        headers = response.headers
        raw = "\n".join([f"{k}: {v}" for k, v in headers.items()])

        faltantes = [h for h in OWASP_HEADERS if h.lower() not in [k.lower() for k in headers.keys()]]

        saida = (
            f"ALVO: {url}\n\n"
            f"HEADERS ENCONTRADOS:\n{raw}\n\n"
            f"AVISO: Headers OWASP faltando: {', '.join(faltantes) if faltantes else 'Nenhum ✅'}"
        )
        storage.salvar(alvo_limpo, "headers", saida)
        return saida
    except Exception as e:
        return str(e)
