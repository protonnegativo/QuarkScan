import os
import subprocess
from langchain_core.tools import tool
from security import FLAGS_PERMITIDAS, validar_args, validar_alvo
from session import ja_executado, registrar
import storage

_MAX_CHARS = 5000


def _truncar(texto: str) -> str:
    if len(texto) <= _MAX_CHARS:
        return texto
    return texto[:_MAX_CHARS] + f"\n... [saída truncada — {len(texto)} chars total]"


@tool
def executar_nmap(alvo: str, argumentos: str, forcar_novo: bool = False) -> str:
    """Executa varredura Nmap no alvo.

    Args:
        alvo: domínio ou IP (ex: exemplo.com, 192.168.1.1)
        argumentos: flags separadas por espaço. Exemplos por objetivo:
            Reconhecimento rápido:      -sT -p 22,80,443
            Todas as portas:            -sT -p- --open
            Top 1000 portas (stealth):  -sS -Pn --top-ports 1000
            Versões detalhadas:         -sV -p 80,443 --version-intensity 5
            Vulnerabilidades:           -sV --script vuln -p 80,443,8080
            Fingerprint completo:       -A -T4
            Análise SSL:                --script ssl-enum-ciphers,ssl-cert -p 443
            Scan furtivo:               -sN | -sF | -sX com -Pn
            Controle de velocidade:     --min-rate 500 --max-rate 2000
            Excluir portas:             --exclude-ports 22,3306
            Host discovery:             -PE | -PS443 | -PA80 | -PU53
        forcar_novo: ignorar cache e re-executar (padrão False)

    Scripts NSE disponíveis: vuln, default, safe, discovery, http-headers,
    http-title, ssl-enum-ciphers, banner, http-methods, http-auth-finder,
    http-robots.txt, ftp-anon, smtp-commands, ssh-hostkey, ssl-cert,
    smb-security-mode, smb-vuln-ms17-010
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    args_validados = validar_args(argumentos)
    if not args_validados:
        return f"Erro: nenhum argumento válido. Flags permitidas: {', '.join(sorted(FLAGS_PERMITIDAS))}"

    if not forcar_novo:
        if ja_executado(alvo_limpo, "nmap", argumentos):
            return "Scan nmap já realizado com esses argumentos nesta sessão."
        cache = storage.resultado_recente(alvo_limpo, "nmap", horas=24)
        if cache:
            registrar(alvo_limpo, "nmap", argumentos)
            return f"[CACHE {cache['timestamp']}] Use forcar_novo=True para re-executar.\n\n{_truncar(cache['resultado'])}"

    registrar(alvo_limpo, "nmap", argumentos)
    comando = ["nmap"] + args_validados + [alvo_limpo]
    print(f"[nmap] Executando: {' '.join(comando)}")

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)
        saida = resultado.stdout or resultado.stderr
        storage.salvar(alvo_limpo, "nmap", saida, {"argumentos": argumentos})
        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW nmap]\n{saida}\n[/RAW]\n")
        return _truncar(saida)
    except subprocess.TimeoutExpired:
        return "Erro: timeout (300s). Use --top-ports ou menos portas."
    except Exception as e:
        return str(e)
