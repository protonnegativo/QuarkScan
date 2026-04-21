import re

FLAGS_PERMITIDAS = {
    # Tipos de scan
    "-sT", "-sS", "-sU", "-sV", "-sN", "-sF", "-sX", "-sn", "-sC",
    # Portas
    "-p", "-p-", "--top-ports", "--exclude-ports",
    # Descoberta de host
    "-Pn", "-PE", "-PS", "-PA", "-PU",
    # Comportamento
    "--open", "-v", "-vv", "-n",
    # Timing
    "-T", "--min-rate", "--max-rate",
    # Detecção
    "-A", "-O", "--version-intensity", "--osscan-guess",
    # Scripts NSE
    "--script", "--script-args",
}

FLAGS_COM_VALOR = {
    "--script", "--script-args",
    "-p", "--exclude-ports",
    "-T",
    "--top-ports", "--min-rate", "--max-rate", "--version-intensity",
}

SCRIPTS_PERMITIDOS = {
    "vuln", "default", "safe", "discovery",
    "http-headers", "http-title", "ssl-enum-ciphers", "banner",
    "http-methods", "http-auth-finder", "http-robots.txt",
    "ftp-anon", "smtp-commands", "ssh-hostkey", "ssl-cert",
    "smb-security-mode", "smb-vuln-ms17-010",
}

_VALIDADORES = {
    "-p":                  r"^[\d,\-]+$",
    "--exclude-ports":     r"^[\d,\-]+$",
    "-T":                  r"^[0-5]$",
    "--top-ports":         r"^\d+$",
    "--min-rate":          r"^\d+$",
    "--max-rate":          r"^\d+$",
    "--version-intensity": r"^[0-9]$",
    "--script-args":       None,
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
                elif resultado and resultado[-1] == "--script":
                    resultado.pop()
            else:
                pattern = _VALIDADORES.get(aguardando_valor_de)
                if pattern is None or re.match(pattern, token):
                    resultado.append(token)
                elif resultado and resultado[-1] == aguardando_valor_de:
                    resultado.pop()
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
