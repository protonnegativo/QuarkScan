from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from prompts import PROMPT_WHATWEB
from tools.whatweb import executar_whatweb
from agents.base import invocar

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_agente = create_react_agent(_llm, tools=[executar_whatweb], prompt=PROMPT_WHATWEB)


@tool
def agente_whatweb(consulta: str) -> str:
    """Agente especializado em fingerprinting de tecnologias web com WhatWeb.
    Use para: identificar CMS, frameworks, servidor web, linguagens, bibliotecas JS.
    Passe a consulta completa incluindo o alvo.
    """
    return invocar(_agente, consulta)
