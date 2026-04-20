import subprocess
from langchain_core.tools import tool
from security import FLAGS_PERMITIDAS, validar_args, validar_alvo


@tool
def executar_nmap(alvo: str, argumentos: str) -> str:
    """Executa varredura Nmap no alvo com os argumentos fornecidos.

    Argumentos devem ser flags nmap separadas por espaço.
    Escolha conforme o objetivo da auditoria:
    - Reconhecimento básico: use -sT com -p e portas específicas
    - Varredura completa de portas: use -sT -p- com --open
    - Detecção de versão: use -sV com -p e portas relevantes
    - Scan de vulnerabilidades: use -sV --script vuln com -p e as portas abertas
    - Fingerprint completo: use -A com -T4

    Scripts disponíveis para --script: vuln, default, safe, discovery,
    http-headers, http-title, ssl-enum-ciphers, banner
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP (ex: exemplo.com, 192.168.1.1)."

    args_validados = validar_args(argumentos)
    if not args_validados:
        return f"Erro: nenhum argumento válido. Flags permitidas: {', '.join(sorted(FLAGS_PERMITIDAS))}"

    comando = ["nmap"] + args_validados + [alvo_limpo]
    print(f"[nmap] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
        return resultado.stdout or resultado.stderr
    except subprocess.TimeoutExpired:
        return "Erro: timeout atingido (300s). Tente um scan mais focado em menos portas."
    except Exception as e:
        return str(e)
