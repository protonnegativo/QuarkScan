import subprocess
from langchain_core.tools import tool
from security import validar_alvo


@tool
def executar_nikto(alvo: str, porta: str = "443", ssl: bool = True) -> str:
    """Executa varredura de vulnerabilidades web com Nikto.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        porta: porta alvo (padrão 443)
        ssl: usar SSL/TLS (padrão True)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    import re
    if not re.match(r"^\d{1,5}$", porta) or not (1 <= int(porta) <= 65535):
        return "Erro: porta inválida."

    comando = [
        "nikto",
        "-h", alvo_limpo,
        "-p", porta,
        "-nointeractive",
        "-maxtime", "120s",
        "-Format", "txt",
    ]

    if ssl:
        comando.append("-ssl")

    print(f"[nikto] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=180)
        saida = resultado.stdout.strip()
        return saida if saida else resultado.stderr or "Nikto não retornou resultados."
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (180s)."
    except FileNotFoundError:
        return "Erro: nikto não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
