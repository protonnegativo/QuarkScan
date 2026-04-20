from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_HEADERS
from tools.headers import analisar_headers

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[analisar_headers], prompt=PROMPT_HEADERS)


def _extrair_conteudo(resultado: dict) -> str:
    conteudo = resultado["messages"][-1].content
    if isinstance(conteudo, list):
        return " ".join(item.get("text", "") if isinstance(item, dict) else str(item) for item in conteudo)
    return conteudo


@tool
def agente_headers(consulta: str) -> str:
    """Agente especializado em análise de headers HTTP e conformidade OWASP.
    Use para: auditar headers de segurança, verificar cookies, identificar information disclosure via headers.
    Passe a consulta completa incluindo o alvo.
    """
    return _extrair_conteudo(_agente.invoke({"messages": [("user", consulta)]}))
