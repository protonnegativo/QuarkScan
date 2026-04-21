import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage


@tool
def executar_whatweb(
    alvo: str,
    agressividade: int = 1,
    perfil_navegador: str = "",
) -> str:
    """Identifica tecnologias, CMS, frameworks e stack do alvo com WhatWeb.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        agressividade: nível de agressividade 1-3
                       1=passivo (padrão), 2=moderado, 3=agressivo
        perfil_navegador: simular navegador real — perfis: chrome, firefox, safari, googlebot
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    nivel = max(1, min(3, int(agressividade)))

    perfil = obter_perfil(perfil_navegador)
    if perfil_navegador and not perfil:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if ja_executado(alvo_limpo, "whatweb", str(nivel), perfil_navegador):
        return "Fingerprinting whatweb já realizado para este alvo nesta sessão. Use o resultado anterior disponível no contexto ou consulte agente_historico."

    registrar(alvo_limpo, "whatweb", str(nivel), perfil_navegador)

    url = f"https://{alvo_limpo}"

    comando = [
        "whatweb",
        f"-a{nivel}",
        "--no-errors",
        "--color=never",
        url,
    ]

    if perfil:
        comando += ["-U", perfil["ua"]]

    print(f"[whatweb] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=60)
        saida = resultado.stdout.strip() or "WhatWeb não detectou tecnologias."
        storage.salvar(alvo_limpo, "whatweb", saida, {"agressividade": nivel, "perfil": perfil_navegador})
        return saida
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (60s)."
    except FileNotFoundError:
        return "Erro: whatweb não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
