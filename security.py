import re

FLAGS_PERMITIDAS = {
    "-sT", "-sV", "-sU", "-sS", "-sn", "-sC",
    "-p", "-p-", "--open", "-A", "-O", "-T",
    "--script", "--script-args",
    "-Pn", "-n", "-v", "-vv",
}

FLAGS_COM_VALOR = {"--script", "--script-args", "-p", "-T"}

SCRIPTS_PERMITIDOS = {
    "vuln", "default", "safe", "discovery",
    "http-headers", "http-title", "ssl-enum-ciphers", "banner",
}


def validar_args(argumentos: str) -> list:
    tokens = argumentos.split()
    resultado = []
    aguardando_valor_de = None

    for token in tokens:
        if aguardando_valor_de:
            if aguardando_valor_de == "--script":
                scripts = [s.strip() for s in token.split(",") if s.strip() in SCRIPTS_PERMITIDOS]
                if scripts:
                    resultado.append(",".join(scripts))
                else:
                    if resultado and resultado[-1] == "--script":
                        resultado.pop()
            elif aguardando_valor_de in {"-p", "-T"}:
                if re.match(r"^[\d,\-]+$", token):
                    resultado.append(token)
                elif resultado and resultado[-1] in {"-p", "-T"}:
                    resultado.pop()
            else:
                resultado.append(token)
            aguardando_valor_de = None
        else:
            if any(token == f or token.startswith(f) for f in FLAGS_PERMITIDAS):
                resultado.append(token)
                if token in FLAGS_COM_VALOR:
                    aguardando_valor_de = token

    return resultado


def validar_alvo(alvo: str) -> str | None:
    alvo_limpo = alvo.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if re.match(r"^[a-zA-Z0-9.\-]+$", alvo_limpo):
        return alvo_limpo
    return None
