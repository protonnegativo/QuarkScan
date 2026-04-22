from langchain_core.tools import tool
from llm import criar_llm
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_WHATWEB
from tools.whatweb import executar_whatweb
from agents.base import invocar

_llm = criar_llm("whatweb")
_agente = create_react_agent(_llm, tools=[executar_whatweb], prompt=PROMPT_WHATWEB)


@tool
def agente_whatweb(consulta: str) -> str:
    """Agente especializado em fingerprinting de tecnologias web com WhatWeb.
    Use para: identificar CMS, frameworks, servidor web, linguagens, bibliotecas JS.
    Passe a consulta completa incluindo o alvo.
    """
    return invocar(_agente, consulta)
