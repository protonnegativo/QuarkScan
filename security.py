import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional, Tuple

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


_INPUT_MAX_LEN = 2000
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitizar_input(texto: str) -> str:
    """Remove caracteres de controle e limita o tamanho do input do usuário."""
    texto = _CTRL_RE.sub("", texto)
    if len(texto) > _INPUT_MAX_LEN:
        texto = texto[:_INPUT_MAX_LEN]
    return texto.strip()


def validar_alvo(alvo: str) -> str | None:
    alvo_limpo = alvo.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if re.match(r"^[a-zA-Z0-9.\-]+$", alvo_limpo):
        return alvo_limpo
    return None


# ─── Validation Guardrails ────────────────────────────────────────────────────

_RGX_SHELL_META  = re.compile(r'[;|&`$(){}<>]')
_RGX_PATH_TRAV   = re.compile(r'\.\.[/\\]')
_RGX_REDIRECT    = re.compile(r'(?<![=<>])[<>]|>>')
_RGX_BACKTICK    = re.compile(r'`[^`]{1,200}`')
_RGX_CMD_SUBST   = re.compile(r'\$\([^)]{1,200}\)')
_RGX_ENCODED     = re.compile(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}')
_RGX_NEWLINE     = re.compile(r'\\n|\\r|\n|\r')
_RGX_NULL_BYTE   = re.compile(r'\\x00|%00')
_RGX_FLAG_INJECT = re.compile(r'--[a-zA-Z]+=.*[;|&]')

_CHECKS_REGEX: list[tuple] = [
    (_RGX_SHELL_META,  "metacaracteres de shell (;|&`$(){}<>)"),
    (_RGX_PATH_TRAV,   "path traversal (../)"),
    (_RGX_REDIRECT,    "redirecionamento de I/O"),
    (_RGX_BACKTICK,    "execução via backtick"),
    (_RGX_CMD_SUBST,   "substituição de comando $()"),
    (_RGX_ENCODED,     "payload URL/hex encoded"),
    (_RGX_NEWLINE,     "injeção de newline"),
    (_RGX_NULL_BYTE,   "null byte"),
    (_RGX_FLAG_INJECT, "injeção via flag de ferramenta"),
]

_TOOLS_DIR = Path(__file__).parent / "tools"


def _tools_autorizadas() -> set[str]:
    return {p.stem for p in _TOOLS_DIR.glob("*.py") if p.stem != "__init__"}


class ValidationGuardrails:
    """
    Camada universal de validação aplicada a toda chamada de ferramenta
    antes de chegar ao subprocess.run().

    Pipeline: autorização → rate-limit → regex → semântica LLM (opcional).
    """

    def __init__(self, llm=None, rate_limit_max: int = 5, rate_window: int = 60):
        self._llm = llm
        self._rate_max = rate_limit_max
        self._rate_window = rate_window
        self._chamadas: dict[str, list[float]] = defaultdict(list)

    def validar(self, ferramenta: str, alvo: str, args: str) -> Tuple[bool, str]:
        """Retorna (True, 'OK') ou (False, motivo_do_bloqueio)."""
        ok, msg = self._check_autorizacao(ferramenta)
        if not ok:
            return False, msg

        ok, msg = self._check_rate_limit(ferramenta, alvo)
        if not ok:
            return False, msg

        ok, msg = self._check_regex(args)
        if not ok:
            return False, msg

        if self._llm:
            ok, msg = self._check_semantico(ferramenta, alvo, args)
            if not ok:
                return False, msg

        return True, "OK"

    def _check_autorizacao(self, ferramenta: str) -> Tuple[bool, str]:
        autorizadas = _tools_autorizadas()
        if ferramenta not in autorizadas:
            return False, (
                f"Ferramenta '{ferramenta}' não encontrada em tools/. "
                f"Autorizadas: {sorted(autorizadas)}"
            )
        return True, "OK"

    def _check_rate_limit(self, ferramenta: str, alvo: str) -> Tuple[bool, str]:
        chave = f"{ferramenta}:{alvo.lower()}"
        agora = time.monotonic()
        janela = [t for t in self._chamadas[chave] if agora - t < self._rate_window]
        self._chamadas[chave] = janela
        if len(janela) >= self._rate_max:
            return False, (
                f"Rate limit: {ferramenta} atingiu {self._rate_max} chamadas "
                f"em {self._rate_window}s para {alvo}"
            )
        self._chamadas[chave].append(agora)
        return True, "OK"

    def _check_regex(self, args: str) -> Tuple[bool, str]:
        for pattern, descricao in _CHECKS_REGEX:
            if pattern.search(args):
                return False, f"Injeção detectada: {descricao} — args={args!r}"
        return True, "OK"

    def _check_semantico(self, ferramenta: str, alvo: str, args: str) -> Tuple[bool, str]:
        """LLM para detectar escape semântico que bypass regex (payloads multi-encode, etc.)."""
        prompt = (
            f"Você é um auditor de segurança. Analise se os argumentos abaixo "
            f"tentam escapar do contexto legítimo da ferramenta '{ferramenta}' "
            f"executando contra o alvo '{alvo}'.\n\n"
            f"Argumentos: {args}\n\n"
            f"Sinais de escape: execução de comandos do SO, acesso a /etc /proc /home, "
            f"reverse shells, exfiltração de dados, payloads multi-encode.\n\n"
            f"Responda SOMENTE:\nSEGURO\nou\nESCAPE: <motivo em uma linha>"
        )
        try:
            resposta = self._llm.invoke(prompt)
            conteudo = getattr(resposta, "content", str(resposta)).strip()
            if conteudo.upper().startswith("ESCAPE"):
                motivo = conteudo.split(":", 1)[1].strip() if ":" in conteudo else conteudo
                return False, f"Escape semântico (LLM): {motivo}"
        except Exception:
            pass  # fail-open: regex já cobre os casos óbvios
        return True, "OK"


# Instância global — inicializada em agente.py após carregar .env
_guardrails: Optional[ValidationGuardrails] = None


def inicializar_guardrails(llm=None) -> None:
    global _guardrails
    _guardrails = ValidationGuardrails(llm=llm)


def guardrail_check(ferramenta: str, alvo: str, args: str) -> None:
    """
    Ponto de entrada único para todos os tools.
    Levanta PermissionError se a chamada for bloqueada.
    """
    if _guardrails is None:
        return
    ok, motivo = _guardrails.validar(ferramenta, alvo, args)
    if not ok:
        raise PermissionError(f"[GUARDRAIL] {motivo}")
