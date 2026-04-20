from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_HISTORICO
from tools.historico import listar_alvos_salvos, consultar_historico, comparar_scans

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(
    _llm,
    tools=[listar_alvos_salvos, consultar_historico, comparar_scans],
    prompt=PROMPT_HISTORICO,
)


def _extrair_conteudo(resultado: dict) -> str:
    conteudo = resultado["messages"][-1].content
    if isinstance(conteudo, list):
        return " ".join(item.get("text", "") if isinstance(item, dict) else str(item) for item in conteudo)
    return conteudo


@tool
def agente_historico(consulta: str) -> str:
    """Agente especializado em consultar o histórico de scans salvos.
    Use para: ver scans anteriores, comparar resultados entre datas, listar alvos já auditados, ver o que mudou.
    Passe a consulta completa incluindo o alvo e o que deseja consultar.
    """
    return _extrair_conteudo(_agente.invoke({"messages": [("user", consulta)]}))
