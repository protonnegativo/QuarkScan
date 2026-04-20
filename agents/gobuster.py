from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_GOBUSTER
from tools.gobuster import executar_gobuster

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_gobuster], prompt=PROMPT_GOBUSTER)


def _extrair_conteudo(resultado: dict) -> str:
    conteudo = resultado["messages"][-1].content
    if isinstance(conteudo, list):
        return " ".join(item.get("text", "") if isinstance(item, dict) else str(item) for item in conteudo)
    return conteudo


@tool
def agente_gobuster(consulta: str) -> str:
    """Agente especializado em enumeração de diretórios e arquivos ocultos com Gobuster.
    Use para: descobrir paths, painéis admin, arquivos sensíveis, estrutura da aplicação.
    Passe a consulta completa incluindo o alvo e o foco da enumeração.
    """
    return _extrair_conteudo(_agente.invoke({"messages": [("user", consulta)]}))
