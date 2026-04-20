from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_SUBFINDER
from tools.subfinder import executar_subfinder

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_subfinder], prompt=PROMPT_SUBFINDER)


def _extrair_conteudo(resultado: dict) -> str:
    conteudo = resultado["messages"][-1].content
    if isinstance(conteudo, list):
        return " ".join(item.get("text", "") if isinstance(item, dict) else str(item) for item in conteudo)
    return conteudo


@tool
def agente_subfinder(consulta: str) -> str:
    """Agente especializado em enumeração passiva de subdomínios com subfinder.
    Use para: descobrir subdomínios, mapear superfície de ataque, reconhecimento passivo de DNS.
    Passe a consulta completa incluindo o domínio alvo.
    """
    return _extrair_conteudo(_agente.invoke({"messages": [("user", consulta)]}))
