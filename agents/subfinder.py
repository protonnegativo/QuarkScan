from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_SUBFINDER
from tools.subfinder import executar_subfinder
from agents.base import invocar

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_subfinder], prompt=PROMPT_SUBFINDER)


@tool
def agente_subfinder(consulta: str) -> str:
    """Agente especializado em enumeração passiva de subdomínios com subfinder.
    Use para: descobrir subdomínios, mapear superfície de ataque, reconhecimento passivo de DNS.
    Passe a consulta completa incluindo o domínio alvo.
    """
    return invocar(_agente, consulta)
