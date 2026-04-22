from langchain_core.tools import tool
from llm import criar_llm
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_HEADERS
from tools.headers import analisar_headers
from agents.base import invocar

_llm = criar_llm("headers")
_agente = create_react_agent(_llm, tools=[analisar_headers], prompt=PROMPT_HEADERS)


@tool
def agente_headers(consulta: str) -> str:
    """Agente especializado em análise de headers HTTP e conformidade OWASP.
    Use para: auditar headers de segurança, verificar cookies, identificar information disclosure via headers.
    Passe a consulta completa incluindo o alvo.
    """
    return invocar(_agente, consulta)
