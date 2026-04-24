import os
import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo, guardrail_check
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage

_EVASAO_RE = re.compile(r"^[1-8](,[1-8])*$")
_PORT_RE = re.compile(r"^\d{1,5}$")
_PLUGIN_RE = re.compile(r"^[a-zA-Z0-9_,]+$")
_MAX_CHARS = 6000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_nikto(
    alvo: str,
    porta: str = "80",
    ssl: bool = False,
    evasao: str = "",
    raiz: str = "/",
    vhost: str = "",
    plugins: str = "",
    pausa: int = 0,
    perfil_navegador: str = "",
    forcar_novo: bool = False,
) -> str:
    """Executa varredura de vulnerabilidades web com Nikto.

    Args:
        alvo: domínio ou IP (ex: exemplo.com)
        porta: porta alvo (padrão 80; use 443 com ssl=True)
        ssl: usar SSL/TLS (padrão False)
        evasao: técnicas IDS separadas por vírgula — ex: "1,2,6"
                1=maiúsculas  2=barra  3=URL-encode  5=fake-param  6=TAB  8=aleatório
        raiz: prefixo de path (ex: "/api", "/app"). Padrão "/"
        vhost: virtual host alternativo para o header Host
        plugins: plugins Nikto (ex: "headers,robots"). "ALL" para todos
        pausa: pausa em segundos entre requisições (0 = sem pausa)
        perfil_navegador: chrome, firefox, safari, googlebot
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    if not _PORT_RE.match(porta) or not (1 <= int(porta) <= 65535):
        return "Erro: porta inválida. Use um número entre 1 e 65535."

    if evasao and not _EVASAO_RE.match(evasao):
        return "Erro: evasao inválida. Use dígitos de 1-8 separados por vírgula (ex: '1,2,6')."

    if plugins and not _PLUGIN_RE.match(plugins):
        return "Erro: plugins inválidos. Use nomes alfanuméricos separados por vírgula."

    if pausa < 0 or pausa > 60:
        return "Erro: pausa deve estar entre 0 e 60 segundos."

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    try:
        guardrail_check("nikto", alvo_limpo, f"-h {alvo_limpo} -p {porta}")
    except PermissionError as e:
        return str(e)

    chave_extra = f"{porta}{evasao}{plugins}"
    if not forcar_novo:
        if ja_executado(alvo_limpo, "nikto", chave_extra):
            return "Varredura nikto já realizada para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "nikto", horas=24)
        if cache:
            registrar(alvo_limpo, "nikto", chave_extra)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "nikto", chave_extra)

    comando = [
        "nikto",
        "-h", alvo_limpo,
        "-p", porta,
        "-root", raiz,
        "-maxtime", "300s",
        "-nointeractive",
        "-Format", "txt",
    ]

    if ssl:
        comando.append("-ssl")

    if evasao:
        for tecnica in evasao.split(","):
            comando += ["-evasion", tecnica.strip()]

    if vhost:
        vhost_limpo = validar_alvo(vhost)
        if vhost_limpo:
            comando += ["-vhost", vhost_limpo]

    if plugins:
        comando += ["-Plugins", plugins]

    if pausa > 0:
        comando += ["-pause", str(pausa)]

    if perfil:
        comando += ["-useragent", perfil["ua"]]

    print(f"[nikto] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=360)
        saida = resultado.stdout.strip() or resultado.stderr.strip()
        if not saida:
            saida = "Nenhum resultado retornado pelo Nikto."
        storage.salvar(alvo_limpo, "nikto", saida, {
            "porta": porta, "ssl": ssl, "evasao": evasao, "plugins": plugins,
        })
        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW nikto]\n{saida}\n[/RAW]\n")
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return "Erro: timeout (360s). Tente com plugins específicos ou porta diferente."
    except FileNotFoundError:
        return "Erro: nikto não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
