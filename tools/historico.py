import re
from langchain_core.tools import tool
from security import validar_alvo
import storage


def _extrair_itens(ferramenta: str, texto: str) -> set[str]:
    linhas = [l.strip() for l in texto.splitlines() if l.strip()]

    if ferramenta == "nmap":
        return {l for l in linhas if re.match(r"^\d+/(tcp|udp)\s+\w+", l)}

    if ferramenta == "subfinder":
        return {l for l in linhas if not l.startswith("##") and not l.startswith("...")}

    if ferramenta == "gobuster":
        return {l for l in linhas if l.startswith("/")}

    if ferramenta == "headers":
        return {
            l for l in linhas
            if (":" in l and not l.startswith("ALVO"))
            or l.startswith("OWASP")
            or l.startswith("AVISO")
        }

    if ferramenta == "nuclei":
        return {
            re.sub(r"^\[[\d\-: ]+\]\s*", "", l)
            for l in linhas
            if l.startswith("[")
        }

    if ferramenta in ("nikto", "whatweb"):
        return {
            l for l in linhas
            if not re.match(r"^[-\s]*Nikto", l)
            and not re.search(r"\d{4}-\d{2}-\d{2}", l)
        }

    return set(linhas)


@tool
def listar_alvos_salvos() -> str:
    """Lista todos os alvos já escaneados e salvos no histórico."""
    lista = storage.alvos()
    if not lista:
        return "Nenhum scan salvo ainda."

    linhas = ["Alvos no histórico:\n"]
    for a in lista:
        linhas.append(f"  {a['alvo']}")
        linhas.append(f"    Scans: {a['total']}  |  Ferramentas: {a['ferramentas']}")
        linhas.append(f"    Primeiro: {a['primeiro']}  |  Último: {a['ultimo']}\n")
    return "\n".join(linhas)


@tool
def consultar_historico(alvo: str, ferramenta: str = "") -> str:
    """Consulta scans anteriores salvos para um alvo.

    Args:
        alvo: domínio ou IP do alvo
        ferramenta: filtrar por ferramenta (opcional) — nmap, headers, gobuster, nikto, nuclei, whatweb, subfinder
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido."

    registros = storage.historico(alvo_limpo, ferramenta or None, limite=10)
    if not registros:
        return f"Nenhum scan encontrado para {alvo_limpo}."

    linhas = [f"Histórico de {alvo_limpo}:\n"]
    for r in registros:
        linhas.append(f"[{r['timestamp']}] {r['ferramenta']}  (ID: {r['id']})")
        if r["parametros"]:
            linhas.append(f"  Parâmetros: {r['parametros']}")
        preview = r["resultado"][:1000]
        if len(r["resultado"]) > 1000:
            preview += "..."
        linhas.append(f"  {preview}\n")
    return "\n".join(linhas)


@tool
def comparar_scans(alvo: str, ferramenta: str) -> str:
    """Compara os dois últimos scans de uma ferramenta para ver o que mudou.

    Args:
        alvo: domínio ou IP do alvo
        ferramenta: nmap, headers, gobuster, nikto, nuclei, whatweb ou subfinder
    """
    alvo_limpo = validar_alvo(alvo)
    if not alvo_limpo:
        return "Erro: alvo inválido."

    atual, anterior = storage.ultimos_dois(alvo_limpo, ferramenta)
    if not atual:
        return f"Nenhum scan de {ferramenta} encontrado para {alvo_limpo}."
    if not anterior:
        return f"Apenas um scan de {ferramenta} disponível. Execute novamente para comparar."

    novo = _extrair_itens(ferramenta, atual["resultado"])
    antigo = _extrair_itens(ferramenta, anterior["resultado"])

    adicionados = sorted(novo - antigo)
    removidos = sorted(antigo - novo)

    linhas = [
        f"Comparação {ferramenta} — {alvo_limpo}",
        f"Scan anterior : {anterior['timestamp']}",
        f"Scan atual    : {atual['timestamp']}",
        "",
    ]

    if adicionados:
        linhas.append("NOVO:")
        linhas.extend(f"  + {l}" for l in adicionados)
    if removidos:
        linhas.append("\nREMOVIDO:")
        linhas.extend(f"  - {l}" for l in removidos)
    if not adicionados and not removidos:
        linhas.append("Nenhuma alteração detectada.")

    return "\n".join(linhas)
