import os
from langchain_google_genai import ChatGoogleGenerativeAI

_PADRAO = "gemini-2.5-flash"


def criar_llm(agente: str = "") -> ChatGoogleGenerativeAI:
    """
    Resolve o modelo a usar na seguinte ordem de prioridade:
      1. GEMINI_MODEL_<AGENTE>  (ex: GEMINI_MODEL_NMAP)
      2. GEMINI_MODEL           (padrão global)
      3. gemini-2.5-flash       (fallback hardcoded)
    """
    model = (
        os.getenv(f"GEMINI_MODEL_{agente.upper()}") if agente else None
    ) or os.getenv("GEMINI_MODEL", _PADRAO)
    return ChatGoogleGenerativeAI(model=model, temperature=0)
