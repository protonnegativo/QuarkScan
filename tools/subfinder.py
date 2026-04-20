import subprocess
from langchain_core.tools import tool
from security import validar_alvo
import storage


@tool
def executar_subfinder(alvo: str) -> str:
    """Enumera subdomínios do alvo via reconhecimento passivo com subfinder.

    Args:
        alvo: domínio alvo (ex: exemplo.com)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use um domínio válido."

    comando = [
        "subfinder",
        "-d", alvo_limpo,
        "-silent",
        "-timeout", "30",
    ]

    print(f"[subfinder] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=120)
        saida = resultado.stdout.strip() or "Nenhum subdomínio encontrado."
        storage.salvar(alvo_limpo, "subfinder", saida)
        return saida
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (120s)."
    except FileNotFoundError:
        return "Erro: subfinder não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
