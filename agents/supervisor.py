from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

from agents.bypass_analyst import agente_bypass_analyst
from agents.gobuster import agente_gobuster
from agents.headers import agente_headers
from agents.historico import agente_historico
from agents.nikto import agente_nikto
from agents.nmap import agente_nmap
from agents.nuclei import agente_nuclei
from agents.subfinder import agente_subfinder
from agents.whatweb import agente_whatweb
from llm import criar_llm
from prompts import PROMPT_SUPERVISOR

_llm = criar_llm("supervisor")
_memoria = MemorySaver()

supervisor = create_react_agent(
    _llm,
    tools=[
        agente_nmap,
        agente_headers,
        agente_gobuster,
        agente_nikto,
        agente_nuclei,
        agente_whatweb,
        agente_subfinder,
        agente_historico,
        agente_bypass_analyst(),
    ],
    checkpointer=_memoria,
    prompt=PROMPT_SUPERVISOR,
)
