from langchain_core.tools import tool
from llm import criar_llm
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_SUBFINDER
from tools.subfinder import executar_subfinder
from agents.base import invocar

_llm = criar_llm("subfinder")
_agente = create_react_agent(_llm, tools=[executar_subfinder], prompt=PROMPT_SUBFINDER)


@tool
def agente_subfinder(consulta: str) -> str:
    """Agente especializado em enumeração passiva de subdomínios com subfinder.
    Use para: descobrir subdomínios, mapear superfície de ataque, reconhecimento passivo de DNS.
    Passe a consulta completa incluindo o domínio alvo.
    """
    return invocar(_agente, consulta)
