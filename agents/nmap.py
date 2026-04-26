from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from agents.base import invocar
from llm import criar_llm
from prompts import PROMPT_NMAP
from tools.nmap import executar_nmap

_llm = criar_llm("nmap")
_agente = create_react_agent(_llm, tools=[executar_nmap], prompt=PROMPT_NMAP)


@tool
def agente_nmap(consulta: str) -> str:
    """Agente especializado em varredura de rede com Nmap.
    Use para: reconhecimento de portas, detecção de serviços, fingerprinting, análise de infraestrutura.
    Passe a consulta completa incluindo o alvo e o tipo de scan desejado.
    """
    return invocar(_agente, consulta)
