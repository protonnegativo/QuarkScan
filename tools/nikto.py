import re
import subprocess
from langchain_core.tools import tool
from security import validar_alvo
from profiles import obter_perfil, perfis_disponiveis
from session import ja_executado, registrar
import storage


@tool
def executar_nikto(
    alvo: str,
    porta: str = "443",
    ssl: bool = True,
    perfil_navegador: str = "",
    evasao: str = "",
    pausa: int = 0,
) -> str:
    """Executa varredura de vulnerabilidades web com Nikto.

    Args:
        alvo: domínio ou IP do alvo (ex: exemplo.com)
        porta: porta alvo (padrão 443)
        ssl: usar SSL/TLS (padrão True)
        perfil_navegador: simular navegador real para contornar WAF — perfis disponíveis: chrome, firefox, safari, googlebot
        evasao: técnicas de evasão de IDS/WAF separadas por vírgula (ex: "1,2,6")
                1=aleatoriza maiúsculas, 2=adiciona barra, 3=URL encode,
                5=fake parâmetro, 6=adiciona TAB, 8=aleatório
        pausa: segundos de pausa entre requisições para scan mais lento (0=sem pausa, máx 60)
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido. Use domínio ou IP."

    if not re.match(r"^\d{1,5}$", porta) or not (1 <= int(porta) <= 65535):
        return "Erro: porta inválida."

    if pausa < 0 or pausa > 60:
        return "Erro: pausa deve estar entre 0 e 60 segundos."

    if ja_executado(alvo_limpo, "nikto", porta, str(ssl), evasao):
        return "Scan nikto já realizado com esses parâmetros nesta sessão. Use o resultado anterior disponível no contexto ou consulte agente_historico."

    registrar(alvo_limpo, "nikto", porta, str(ssl), evasao)

    comando = [
        "nikto",
        "-h", alvo_limpo,
        "-p", porta,
        "-nointeractive",
        "-maxtime", "300s",
    ]

    if ssl:
        comando.append("-ssl")

    perfil = obter_perfil(perfil_navegador)
    if perfil:
        comando += ["-useragent", perfil["ua"]]
    elif perfil_navegador:
        return f"Perfil inválido. Disponíveis: {perfis_disponiveis()}"

    if evasao and re.match(r"^[1-8](,[1-8])*$", evasao):
        comando += ["-evasion", evasao.replace(",", "")]

    if pausa > 0:
        comando += ["-pause", str(pausa)]

    print(f"[nikto] Executando: {' '.join(comando)}")

    timeout = 180 + (pausa * 100)
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        saida = resultado.stdout.strip() or resultado.stderr or "Nikto não retornou resultados."
        storage.salvar(alvo_limpo, "nikto", saida, {"porta": porta, "ssl": ssl, "perfil": perfil_navegador, "evasao": evasao})
        return saida
    except subprocess.TimeoutExpired:
        return f"Erro: timeout atingido ({timeout}s)."
    except FileNotFoundError:
        return "Erro: nikto não encontrado. Verifique a instalação."
    except Exception as e:
        return str(e)
