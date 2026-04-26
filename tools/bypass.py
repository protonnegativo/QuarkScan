import json
import hashlib
import os
from langchain_core.tools import tool
import storage

_ASSINATURAS_WAF = {
    "sqli": [
        "UNION SELECT", "OR 1=1", "'; DROP", "--",
        "information_schema", "SLEEP(", "BENCHMARK(",
        "LOAD_FILE", "INTO OUTFILE",
    ],
    "xss": [
        "<script>", "javascript:", "onerror=", "onload=",
        "alert(", "document.cookie", "eval(", "innerHTML",
    ],
    "lfi": ["../etc/passwd", "....//", "%2e%2e%2f", "php://filter"],
    "rce": ["system(", "exec(", "|id", "|whoami", "passthru(", "`id`"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
    "xxe": ["<!ENTITY", "SYSTEM", "file:///", "expect://"],
    "ssrf": ["169.254.169.254", "localhost", "127.0.0.1", "file://"],
}

_TECNICAS_BYPASS = [
    "URL encoding (%XX)",
    "Double URL encoding (%25XX)",
    "Unicode encoding (\\uXXXX)",
    "Case variation (ScRiPt, SeLeCt)",
    "Whitespace injection (tab, newline, CR)",
    "Comentários SQL (/**/, #, --)",
    "String concatenation (CHAR(), CONCAT())",
    "HTML entity encoding (&lt; &gt;)",
    "Mixed encoding (parcialmente encoded)",
    "Null bytes (%00) para truncar contexto",
    "HTTP Parameter Pollution",
    "Fragmentação em múltiplos parâmetros",
]

_TIPOS_VALIDOS = set(_ASSINATURAS_WAF.keys())
_MAX_CHARS = 4000


@tool
def analisar_bypass_waf(
    payload_original: str,
    tipo_vulnerabilidade: str,
    wafs_alvo: str = "modsecurity-crs,cloudflare,aws-waf",
    num_variacoes: int = 4,
) -> str:
    """Analisa um payload de exploit e gera variações de bypass para WAFs especificados.
    NÃO executa os payloads — apenas análise estática e geração de variações.

    Args:
        payload_original: payload a analisar (ex: "' OR 1=1--", "<script>alert(1)</script>")
        tipo_vulnerabilidade: sqli | xss | lfi | rce | ssti | xxe | ssrf
        wafs_alvo: WAFs alvo separados por vírgula
                   Suportados: modsecurity-crs, cloudflare, aws-waf, imperva, f5-bigip
        num_variacoes: número de variações a gerar (2-6)
    """
    tipo = tipo_vulnerabilidade.lower().strip()
    if tipo not in _TIPOS_VALIDOS:
        return f"Erro: tipo inválido '{tipo}'. Válidos: {sorted(_TIPOS_VALIDOS)}"

    num_variacoes = max(2, min(6, int(num_variacoes)))

    cache_key = hashlib.sha256(
        f"{payload_original}:{tipo}:{wafs_alvo}".encode()
    ).hexdigest()[:20]

    cached = storage.resultado_recente(
        alvo=f"__bypass__{cache_key}",
        ferramenta="bypass_analyst",
        horas=168,
    )
    if cached:
        return f"[CACHE 7d] {cached['resultado']}"

    assinaturas_locais = [
        sig for sig in _ASSINATURAS_WAF.get(tipo, [])
        if sig.lower() in payload_original.lower()
    ]

    from llm import criar_llm
    llm = criar_llm("bypass_analyst")

    prompt = (
        f"Você é um especialista em evasão de WAF (Red Team).\n"
        f"Analise o payload abaixo e gere {num_variacoes} variações de bypass.\n\n"
        f"PAYLOAD ORIGINAL: {payload_original}\n"
        f"TIPO: {tipo}\n"
        f"WAFs ALVO: {wafs_alvo}\n"
        f"ASSINATURAS DETECTADAS LOCALMENTE: {assinaturas_locais}\n\n"
        f"TÉCNICAS DISPONÍVEIS:\n"
        + "\n".join(f"- {t}" for t in _TECNICAS_BYPASS)
        + "\n\nResponda SOMENTE com JSON válido:\n"
        '{\n'
        '  "payload_original": "...",\n'
        '  "assinaturas_waf_detectadas": ["lista de regras que bloqueiam"],\n'
        '  "variacoes": [\n'
        '    {\n'
        '      "id": 1,\n'
        '      "tecnica": "nome da técnica",\n'
        '      "payload": "payload modificado",\n'
        '      "probabilidade_evasao_pct": 70,\n'
        '      "wafs_evadidos": ["cloudflare"],\n'
        '      "wafs_ainda_bloqueiam": ["modsecurity-crs"],\n'
        '      "racional": "por que esta variação evade"\n'
        '    }\n'
        '  ],\n'
        '  "recomendacao": "id da melhor variação e motivo"\n'
        '}\n\n'
        "RESTRIÇÕES:\n"
        "- Não execute nenhum payload\n"
        "- Probabilidade deve ser estimativa honesta (0-95%)\n"
        "- Foque em técnicas que diferenciam os WAFs listados"
    )

    try:
        resposta = llm.invoke(prompt)
        conteudo = getattr(resposta, "content", str(resposta)).strip()

        # Remove markdown code fences se presentes
        if conteudo.startswith("```"):
            linhas = conteudo.splitlines()
            conteudo = "\n".join(
                l for l in linhas
                if not l.strip().startswith("```")
            ).strip()

        json.loads(conteudo)  # valida JSON antes de salvar

        storage.salvar(
            alvo=f"__bypass__{cache_key}",
            ferramenta="bypass_analyst",
            resultado=conteudo,
            parametros={"tipo": tipo, "wafs": wafs_alvo, "payload_hash": cache_key},
            raw_output=conteudo,
        )

        if os.environ.get("QUARKSCAN_RAW"):
            print(f"\n[RAW bypass]\n{conteudo}\n[/RAW]\n")

        return conteudo[:_MAX_CHARS]
    except json.JSONDecodeError:
        return f"Erro: LLM retornou formato inválido. Tente novamente.\nRaw: {conteudo[:300]}"
    except Exception as e:
        return f"Erro na análise de bypass: {e}"
