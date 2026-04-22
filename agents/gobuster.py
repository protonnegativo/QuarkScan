from langchain_core.tools import tool
from llm import criar_llm
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_GOBUSTER
from tools.gobuster import executar_gobuster
from agents.base import invocar

_llm = criar_llm("gobuster")
_agente = create_react_agent(_llm, tools=[executar_gobuster], prompt=PROMPT_GOBUSTER)


@tool
def agente_gobuster(consulta: str) -> str:
    """Agente especializado em enumeração de diretórios e arquivos ocultos com Gobuster.
    Use para: descobrir paths, painéis admin, arquivos sensíveis, estrutura da aplicação.
    Passe a consulta completa incluindo o alvo e o foco da enumeração.
    """
    return invocar(_agente, consulta)
