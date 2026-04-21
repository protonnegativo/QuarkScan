from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_NMAP
from tools.nmap import executar_nmap
from agents.base import invocar

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_nmap], prompt=PROMPT_NMAP)


@tool
def agente_nmap(consulta: str) -> str:
    """Agente especializado em varredura de rede com Nmap.
    Use para: reconhecimento de portas, detecção de serviços, fingerprinting, análise de infraestrutura.
    Passe a consulta completa incluindo o alvo e o tipo de scan desejado.
    """
    return invocar(_agente, consulta)
