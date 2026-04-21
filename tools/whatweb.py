import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage

_MAX_CHARS = 3000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_whatweb(
    alvo: str,
    agressividade: int = 1,
    perfil_navegador: str = "",
    threads: int = 1,
    timeout: int = 30,
    seguir_redirect: str = "never",
    forcar_novo: bool = False,
) -> str:
    """Identifica tecnologias, CMS, frameworks e stack com WhatWeb.

    Args:
        alvo: domínio ou IP (ex: exemplo.com)
        agressividade: 1=passivo (padrão)  2=moderado (múltiplas requisições)
                       3=agressivo (fuzzing de plugins, máximo de detecções)
        perfil_navegador: chrome, firefox, safari, googlebot
        threads: threads paralelas (padrão 1, máx 20)
                 use >1 apenas para múltiplos alvos ou agressividade=3
        timeout: timeout de conexão em segundos (padrão 30, máx 120)
        seguir_redirect: "never" (padrão), "http_only", "always"
                         "always" pode revelar redirecionamentos para apps internas
        forcar_novo: ignorar cache e re-executar (padrão False)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    nivel = max(1, min(3, int(agressividade)))
    threads = max(1, min(20, int(threads)))
    timeout = max(5, min(120, int(timeout)))

    redirect_opcoes = {"never", "http_only", "always"}
    if seguir_redirect not in redirect_opcoes:
        return f"Erro: seguir_redirect deve ser um de: {sorted(redirect_opcoes)}"

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if not forcar_novo:
        if ja_executado(alvo_limpo, "whatweb", str(nivel), perfil_navegador):
            return "Fingerprinting whatweb já realizado para este alvo nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "whatweb", horas=48)
        if cache:
            registrar(alvo_limpo, "whatweb", str(nivel), perfil_navegador)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "whatweb", str(nivel), perfil_navegador)

    url = f"https://{alvo_limpo}"

    comando = [
        "whatweb",
        f"-a{nivel}",
        "--no-errors",
        "--color=never",
        "-t", str(threads),
        f"--open-timeout={timeout}",
        f"--read-timeout={timeout}",
        f"--follow-redirect={seguir_redirect}",
        url,
    ]

    if perfil:
        comando += ["-U", perfil["ua"]]

    print(f"[whatweb] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout + 30)
        saida = resultado.stdout.strip() or "WhatWeb não detectou tecnologias."
        storage.salvar(alvo_limpo, "whatweb", saida, {
            "agressividade": nivel, "perfil": perfil_navegador,
        })
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return f"Erro: timeout ({timeout + 30}s)."
    except FileNotFoundError:
        return "Erro: whatweb não encontrado."
    except Exception as e:
        return str(e)
