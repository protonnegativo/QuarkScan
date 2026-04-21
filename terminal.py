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
    MAGENTA = "\033[95m"


def formatar_para_terminal(texto: str) -> str:
    linhas = texto.split("\n")
    saida = []

    for linha in linhas:
        # Cabeçalho de seção
        if linha.startswith("### "):
            titulo = linha[4:].strip()
            saida.append(f"\n{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}  {titulo}{C.RESET}")
            saida.append(f"{C.CYAN}{C.BOLD}{chr(9472) * 60}{C.RESET}")

        # Marcador de cache
        elif linha.strip().startswith("[CACHE "):
            data = linha.strip()
            saida.append(f"\n  {C.MAGENTA}{C.BOLD}⚡ {data}{C.RESET}")

        # Item de lista com negrito
        elif re.match(r"^\s*[\*\-] \*\*", linha):
            conteudo_l = re.sub(
                r"\*\*(.+?)\*\*",
                lambda m: f"{C.YELLOW}{C.BOLD}{m.group(1)}{C.RESET}",
                linha.strip().lstrip("*- "),
            )
            saida.append(f"\n  {C.YELLOW}{chr(9654)}{C.RESET} {conteudo_l}")

        # Sub-item com negrito
        elif re.match(r"^\s{2,}- \*\*", linha):
            label = re.search(r"\*\*(.+?)\*\*", linha)
            resto = re.sub(r"\*\*(.+?)\*\*[:\s]*", "", linha).strip().lstrip("- ")
            if label:
                chave = label.group(1)
                if any(w in chave for w in ["Risco", "CVE", "Vuln", "Severidade"]):
                    cor = C.RED
                elif any(w in chave for w in ["Mitiga", "Melhoria", "Configura", "serve", "Recomenda", "Correção"]):
                    cor = C.GREEN
                else:
                    cor = C.WHITE
                saida.append(f"      {cor}{C.BOLD}{chave}:{C.RESET} {resto}")

        # Linha com negrito genérico
        elif "**" in linha:
            limpo = re.sub(
                r"\*\*(.+?)\*\*",
                lambda m: f"{C.BOLD}{m.group(1)}{C.RESET}",
                linha,
            )
            saida.append(f"  {limpo}")

        # Linha com código inline
        elif "`" in linha:
            limpo = re.sub(r"`(.+?)`", lambda m: f"{C.GRAY}{m.group(1)}{C.RESET}", linha)
            saida.append(f"  {limpo}")

        # Linha de diff (nova / removida)
        elif re.match(r"^\s*\+\s", linha):
            saida.append(f"  {C.GREEN}{linha}{C.RESET}")
        elif re.match(r"^\s*-\s", linha):
            saida.append(f"  {C.RED}{linha}{C.RESET}")

        elif linha.strip() == "":
            saida.append("")

        else:
            saida.append(f"  {linha}")

    return "\n".join(saida)
