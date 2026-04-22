from langchain_core.tools import tool
from llm import criar_llm
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_NUCLEI
from tools.nuclei import executar_nuclei
from agents.base import invocar

_llm = criar_llm("nuclei")
_agente = create_react_agent(_llm, tools=[executar_nuclei], prompt=PROMPT_NUCLEI)


@tool
def agente_nuclei(consulta: str) -> str:
    """Agente especializado em varredura de vulnerabilidades com Nuclei (templates da comunidade).
    Use para: CVEs indexados, exposições, defaults de login, misconfigurações em larga escala.
    Passe a consulta completa incluindo o alvo.
    """
    return invocar(_agente, consulta)
