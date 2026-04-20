from dotenv import load_dotenv
from agents.supervisor import supervisor, config
from terminal import C, formatar_para_terminal

load_dotenv()

print(f"\n{C.CYAN}{C.BOLD}{chr(9552) * 60}{C.RESET}")
print(f"{C.CYAN}{C.BOLD}      AGENTE OWASP {chr(8212)} OFFENSIVE AI READY{C.RESET}")
print(f"{C.CYAN}{C.BOLD}{chr(9552) * 60}{C.RESET}\n")

while True:
    try:
        pergunta = input(f"{C.GREEN}Voce:{C.RESET} ")
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrando.")
        break
    if pergunta.lower() in ["sair", "exit"]:
        break

    print(f"\n{C.GRAY}[Supervisor] Roteando...{C.RESET}")
    resposta = supervisor.invoke({"messages": [("user", pergunta)]}, config=config)
    conteudo = resposta["messages"][-1].content

    if isinstance(conteudo, list):
        texto = " ".join(
            item.get("text", "") if isinstance(item, dict) else str(item)
            for item in conteudo
        )
    else:
        texto = conteudo

    print(formatar_para_terminal(texto))
