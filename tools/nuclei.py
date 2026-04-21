import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from session import ja_executado, registrar
import storage

_TAGS_VALIDAS = {
    "cve", "exposure", "misconfiguration", "default-login",
    "technology", "takeover", "network", "dns", "ssl",
    "fuzzing", "osint", "file",
}

_SEVERIDADES_VALIDAS = {"info", "low", "medium", "high", "critical"}

_MAX_CHARS = 6000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_nuclei(
    alvo: str,
    tags: str = "cve,misconfiguration,exposure",
    severidade: str = "medium,high,critical",
    porta: str = "",
    ssl: bool = True,
    rate_limit: int = 100,
    timeout: int = 10,
    user_agent: str = "",
    proxy: str = "",
    forcar_novo: bool = False,
) -> str:
    """Executa varredura baseada em templates Nuclei.

    Args:
        alvo: domínio ou IP (ex: exemplo.com)
        tags: categorias de templates separadas por vírgula.
              cve              → CVEs indexados (maior cobertura)
              misconfiguration → erros de configuração de servidores/apps
              exposure         → endpoints e arquivos expostos
              default-login    → credenciais padrão em painéis admin
              technology       → fingerprinting de stack
              takeover         → subdomain takeover possível
              ssl              → problemas SSL/TLS
              dns              → exposições via DNS
              network          → serviços de rede
              osint            → reconhecimento passivo
        severidade: info,low,medium,high,critical (separados por vírgula)
        porta: porta customizada (ex: "8080", "8443")
        ssl: usar HTTPS (padrão True)
        rate_limit: requisições por segundo (padrão 100, máx 500)
        timeout: timeout por template em segundos (padrão 10, máx 60)
        user_agent: user-agent customizado
        proxy: HTTP/SOCKS5 proxy (ex: "http://127.0.0.1:8080", "socks5://127.0.0.1:1080")
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    tags_lista = [t.strip().lower() for t in tags.split(",") if t.strip()]
    invalidas = [t for t in tags_lista if t not in _TAGS_VALIDAS]
    if invalidas:
        return f"Erro: tags inválidas: {invalidas}. Válidas: {sorted(_TAGS_VALIDAS)}"

    sev_lista = [s.strip().lower() for s in severidade.split(",") if s.strip()]
    sev_invalidas = [s for s in sev_lista if s not in _SEVERIDADES_VALIDAS]
    if sev_invalidas:
        return f"Erro: severidades inválidas: {sev_invalidas}. Válidas: {sorted(_SEVERIDADES_VALIDAS)}"

    if not (1 <= rate_limit <= 500):
        return "Erro: rate_limit deve estar entre 1 e 500."

    if not (1 <= timeout <= 60):
        return "Erro: timeout deve estar entre 1 e 60."

    if porta and (not re.match(r"^\d{1,5}$", porta) or not (1 <= int(porta) <= 65535)):
        return "Erro: porta inválida."

    if proxy and not re.match(r"^(https?|socks5)://[a-zA-Z0-9.\-:]+(:\d+)?$", proxy):
        return "Erro: proxy inválido. Use http://host:porta ou socks5://host:porta."

    chave_tags = ",".join(sorted(tags_lista))
    chave_sev = ",".join(sorted(sev_lista))
    if not forcar_novo:
        if ja_executado(alvo_limpo, "nuclei", chave_tags, chave_sev):
            return "Scan nuclei já realizado com esses parâmetros nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "nuclei", horas=24)
        if cache:
            registrar(alvo_limpo, "nuclei", chave_tags, chave_sev)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "nuclei", chave_tags, chave_sev)

    protocolo = "https" if ssl else "http"
    url_alvo = f"{protocolo}://{alvo_limpo}"
    if porta:
        url_alvo += f":{porta}"

    comando = [
        "nuclei",
        "-u", url_alvo,
        "-tags", ",".join(tags_lista),
        "-severity", ",".join(sev_lista),
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-no-interactsh",
        "-silent",
    ]

    if user_agent:
        comando += ["-H", f"User-Agent: {user_agent}"]

    if proxy:
        comando += ["-proxy", proxy]

    print(f"[nuclei] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=600)
        saida = resultado.stdout.strip()

        if not saida:
            stderr = resultado.stderr.strip()
            saida = "Nuclei não encontrou vulnerabilidades com os templates e severidades selecionados."
            if stderr and not any(w in stderr for w in ("WARN", "INF", "DBG")):
                saida += f"\n\nDetalhe: {stderr[:500]}"

        storage.salvar(alvo_limpo, "nuclei", saida, {
            "tags": tags, "severidade": severidade, "porta": porta, "ssl": ssl,
        })
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return "Erro: timeout (600s)."
    except FileNotFoundError:
        return "Erro: nuclei não encontrado."
    except Exception as e:
        return str(e)
