from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_NMAP
from tools.nmap import executar_nmap

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_nmap], prompt=PROMPT_NMAP)


def _extrair_conteudo(resultado: dict) -> str:
    conteudo = resultado["messages"][-1].content
    if isinstance(conteudo, list):
        return " ".join(item.get("text", "") if isinstance(item, dict) else str(item) for item in conteudo)
    return conteudo


@tool
def agente_nmap(consulta: str) -> str:
    """Agente especializado em varredura de rede com Nmap.
    Use para: reconhecimento de portas, detecção de serviços, fingerprinting, análise de infraestrutura.
    Passe a consulta completa incluindo o alvo e o tipo de scan desejado.
    """
    return _extrair_conteudo(_agente.invoke({"messages": [("user", consulta)]}))
