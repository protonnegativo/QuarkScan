import subprocess
from langchain_core.tools import tool
from security import validar_alvo


@tool
def executar_whatweb(alvo: str, agressividade: int = 1) -> str:
    """Identifica tecnologias, CMS, frameworks e stack do alvo com WhatWeb.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        agressividade: nível de agressividade 1-3
                       1=passivo (padrão), 2=moderado, 3=agressivo
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    nivel = max(1, min(3, int(agressividade)))
    url = f"https://{alvo_limpo}"

    comando = [
        "whatweb",
        f"-a{nivel}",
        "--no-errors",
        "--color=never",
        url,
    ]

    print(f"[whatweb] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=60)
        saida = resultado.stdout.strip()
        return saida if saida else "WhatWeb não detectou tecnologias."
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (60s)."
    except FileNotFoundError:
        return "Erro: whatweb não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
