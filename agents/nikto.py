from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_NIKTO
from tools.nikto import executar_nikto
from agents.base import invocar

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_nikto], prompt=PROMPT_NIKTO)


@tool
def agente_nikto(consulta: str) -> str:
    """Agente especializado em varredura de vulnerabilidades web com Nikto.
    Use para: detectar CVEs, misconfigurações de servidor, headers inseguros, versões vulneráveis.
    Passe a consulta completa incluindo o alvo.
    """
    return invocar(_agente, consulta)
