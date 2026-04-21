_INVOKE_CONFIG = {"recursion_limit": 10}


def extrair_conteudo(resultado: dict) -> str:
    messages = resultado.get("messages", [])
    if not messages:
        return "Erro: nenhuma resposta recebida do agente."
    conteudo = messages[-1].content
    if isinstance(conteudo, list):
        partes = [
            item.get("text", "") if isinstance(item, dict) else str(item)
            for item in conteudo
        ]
        return "\n".join(p for p in partes if p.strip())
    return str(conteudo) if conteudo is not None else "Erro: resposta vazia."


def invocar(agente, consulta: str) -> str:
    try:
        return extrair_conteudo(
            agente.invoke({"messages": [("user", consulta)]}, config=_INVOKE_CONFIG)
        )
    except Exception as e:
        msg = str(e)
        if "recursion" in msg.lower():
            return "Erro: agente excedeu limite de iterações. Reformule a consulta."
        if "quota" in msg.lower() or "429" in msg:
            return "Erro: quota da API excedida. Aguarde e tente novamente."
        return f"Erro no agente: {msg}"
