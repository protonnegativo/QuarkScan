from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from prompts import PROMPT_SUPERVISOR
from agents.nmap import agente_nmap
from agents.headers import agente_headers
from agents.gobuster import agente_gobuster
from agents.nikto import agente_nikto
from agents.whatweb import agente_whatweb
from agents.subfinder import agente_subfinder
from agents.historico import agente_historico

_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
_memoria = MemorySaver()

supervisor = create_react_agent(
    _llm,
    tools=[agente_nmap, agente_headers, agente_gobuster, agente_nikto, agente_whatweb, agente_subfinder, agente_historico],
    checkpointer=_memoria,
    prompt=PROMPT_SUPERVISOR,
)
