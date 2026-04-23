import os
import uuid
from dotenv import load_dotenv

load_dotenv()

if not os.environ.get("GEMINI_API_KEY"):
    print("\n[!] GEMINI_API_KEY não definida. Configure no arquivo .env e reinicie.")
    exit(1)

from agents.supervisor import supervisor
from pipeline import detectar_alvo_pipeline, executar_pipeline
from security import sanitizar_input
from terminal import C, formatar_para_terminal

config = {"configurable": {"thread_id": str(uuid.uuid4())}}

print(f"\n{C.CYAN}{C.BOLD}{chr(9552) * 60}{C.RESET}")
print(f"{C.CYAN}{C.BOLD}      QuarkScan {chr(8212)} OFFENSIVE AI READY{C.RESET}")
print(f"{C.CYAN}{C.BOLD}{chr(9552) * 60}{C.RESET}\n")

while True:
    try:
        pergunta = input(f"{C.GREEN}Voce:{C.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrando.")
        break

    if not pergunta:
        continue

    pergunta = sanitizar_input(pergunta)

    if pergunta.lower() in ["sair", "exit", "quit"]:
        break

    alvo_pipeline = detectar_alvo_pipeline(pergunta)
    if alvo_pipeline:
        executar_pipeline(alvo_pipeline, supervisor.invoke, config)
        continue

    print(f"\n{C.GRAY}[Supervisor] Roteando...{C.RESET}")

    try:
        resposta = supervisor.invoke({"messages": [("user", pergunta)]}, config=config)
    except Exception as e:
        msg = str(e)
        if "quota" in msg.lower() or "429" in msg:
            print(f"\n{C.RED}[!] Quota da API excedida. Aguarde e tente novamente.{C.RESET}\n")
        else:
            print(f"\n{C.RED}[!] Erro: {msg}{C.RESET}\n")
        continue

    conteudo = resposta["messages"][-1].content

    if isinstance(conteudo, list):
        partes = [
            item.get("text", "") if isinstance(item, dict) else str(item)
            for item in conteudo
        ]
        texto = "\n".join(p for p in partes if p.strip())
    else:
        texto = conteudo or ""

    print(formatar_para_terminal(texto))
