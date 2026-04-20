import re


class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"


def formatar_para_terminal(texto: str) -> str:
    linhas = texto.split("\n")
    saida = []

    for linha in linhas:
        if linha.startswith("### "):
            titulo = linha[4:].strip()
            saida.append(f"\n{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}  {titulo}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")

        elif re.match(r"^\s*[\*\-] \*\*", linha):
            conteudo_l = re.sub(r"\*\*(.+?)\*\*", lambda m: f"{C.YELLOW}{C.BOLD}{m.group(1)}{C.RESET}", linha.strip().lstrip("*- "))
            saida.append(f"\n  {C.YELLOW}{chr(9654)}{C.RESET} {conteudo_l}")

        elif re.match(r"^\s{2,}- \*\*", linha):
            label = re.search(r"\*\*(.+?)\*\*", linha)
            resto = re.sub(r"\*\*(.+?)\*\*[:\s]*", "", linha).strip().lstrip("- ")
            if label:
                chave = label.group(1)
                if any(w in chave for w in ["Risco", "CVE", "Vuln"]):
                    cor = C.RED
                elif any(w in chave for w in ["Mitiga", "Melhoria", "Configura", "serve", "Recomenda"]):
                    cor = C.GREEN
                else:
                    cor = C.WHITE
                saida.append(f"      {cor}{C.BOLD}{chave}:{C.RESET} {resto}")

        elif "**" in linha:
            limpo = re.sub(r"\*\*(.+?)\*\*", lambda m: f"{C.BOLD}{m.group(1)}{C.RESET}", linha)
            saida.append(f"  {limpo}")

        elif "`" in linha:
            limpo = re.sub(r"`(.+?)`", lambda m: f"{C.GRAY}{m.group(1)}{C.RESET}", linha)
            saida.append(f"  {limpo}")

        elif linha.strip() == "":
            saida.append("")

        else:
            saida.append(f"  {linha}")

    return "\n".join(saida)
