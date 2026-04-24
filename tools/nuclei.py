import os
import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo, guardrail_check
from session import ja_executado, registrar
import storage

_TAGS_VALIDAS = {
    "cve", "misconfiguration", "exposure", "default-login",
    "technology", "takeover", "ssl", "dns", "network", "osint",
}
_SEVERIDADES_VALIDAS = {"info", "low", "medium", "high", "critical"}
_PROXY_RE = re.compile(r"^https?://[a-zA-Z0-9.\-]+(:\d+)?$")
_MAX_CHARS = 8000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


def _validar_lista(valor: str, permitidos: set, nome: str) -> tuple[str | None, str | None]:
    if not valor:
        return "", None
    itens = [t.strip().lower() for t in valor.split(",") if t.strip()]
    invalidos = [i for i in itens if i not in permitidos]
    if invalidos:
        return None, f"Erro: {nome} inválido(s): {', '.join(invalidos)}. Permitidos: {', '.join(sorted(permitidos))}"
    return ",".join(itens), None


@tool
def executar_nuclei(
    alvo: str,
    tags: str = "cve,misconfiguration,exposure",
    severidade: str = "medium,high,critical",
    rate_limit: int = 100,
    timeout: int = 10,
    ssl: bool = True,
    proxy: str = "",
    forcar_novo: bool = False,
) -> str:
    """Executa varredura de vulnerabilidades com Nuclei (templates ProjectDiscovery).

    Args:
        alvo: domínio ou IP (ex: exemplo.com)
        tags: tags de templates separadas por vírgula.
              Disponíveis: cve, misconfiguration, exposure, default-login,
              technology, takeover, ssl, dns, network, osint.
              Use tags="" para sem filtro (cobertura máxima).
        severidade: severidades separadas por vírgula.
                    Disponíveis: info, low, medium, high, critical.
                    Use "info,low,medium,high,critical" para todas.
        rate_limit: requisições por segundo (padrão 100)
        timeout: timeout por template em segundos (padrão 10)
        ssl: verificar certificado SSL (padrão True; False para certs autoassinados)
        proxy: rotear via proxy (ex: "http://127.0.0.1:8080" para Burp Suite)
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    tags_validadas, erro = _validar_lista(tags, _TAGS_VALIDAS, "tag")
    if erro:
        return erro

    severidades_validadas, erro = _validar_lista(severidade, _SEVERIDADES_VALIDAS, "severidade")
    if erro:
        return erro

    if not severidades_validadas:
        return "Erro: pelo menos uma severidade deve ser especificada."

    if not (1 <= rate_limit <= 500):
        return "Erro: rate_limit deve estar entre 1 e 500."

    if not (1 <= timeout <= 120):
        return "Erro: timeout deve estar entre 1 e 120 segundos."

    if proxy and not _PROXY_RE.match(proxy):
        return "Erro: proxy inválido. Use http://host:porta ou https://host:porta."

    try:
        guardrail_check("nuclei", alvo_limpo, f"-u {alvo_limpo} -tags {tags_validadas} -severity {severidades_validadas}")
    except PermissionError as e:
        return str(e)

    chave_extra = f"{tags_validadas}{severidades_validadas}"
    if not forcar_novo:
        if ja_executado(alvo_limpo, "nuclei", chave_extra):
            return "Varredura nuclei já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "nuclei", horas=24)
        if cache:
            registrar(alvo_limpo, "nuclei", chave_extra)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "nuclei", chave_extra)

    url = f"https://{alvo_limpo}"

    comando = [
        "nuclei",
        "-u", url,
        "-severity", severidades_validadas,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-silent",
        "-no-color",
    ]

    if tags_validadas:
        comando += ["-tags", tags_validadas]

    if not ssl:
        comando.append("-insecure")

    if proxy:
        comando += ["-proxy", proxy]

    print(f"[nuclei] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=600)
        saida = resultado.stdout.strip()
        if not saida and resultado.stderr.strip():
            saida = resultado.stderr.strip()
        if not saida:
            saida = "Nenhuma vulnerabilidade encontrada com os templates e filtros especificados."
        storage.salvar(alvo_limpo, "nuclei", saida, {
            "tags": tags_validadas, "severidade": severidades_validadas,
            "rate_limit": rate_limit, "timeout": timeout,
        })
        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW nuclei]\n{saida}\n[/RAW]\n")
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return "Erro: timeout (600s). Reduza o escopo com tags mais específicas."
    except FileNotFoundError:
        return "Erro: nuclei não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
