from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from agents.base import invocar
from llm import criar_llm
from prompts import PROMPT_HISTORICO
from tools.historico import comparar_scans, consultar_historico, listar_alvos_salvos

_llm = criar_llm("historico")
_agente = create_react_agent(
    _llm,
    tools=[listar_alvos_salvos, consultar_historico, comparar_scans],
    prompt=PROMPT_HISTORICO,
)


@tool
def agente_historico(consulta: str) -> str:
    """Agente especializado em consultar o histórico de scans salvos.
    Use para: ver scans anteriores, comparar resultados entre datas, listar alvos já auditados, ver o que mudou.
    Passe a consulta completa incluindo o alvo e o que deseja consultar.
    """
    return invocar(_agente, consulta)
