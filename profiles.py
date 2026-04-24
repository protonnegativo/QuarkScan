PERFIS = {
    "chrome": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        },
    },
    "firefox": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        },
    },
    "safari": {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        },
    },
    "googlebot": {
        "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "headers": {
            "Accept": "*/*",
            "Accept-Language": "en",
        },
    },
}


def obter_perfil(nome: str) -> dict:
    """Retorna o perfil pelo nome ou dict vazio se não encontrado."""
    return PERFIS.get(nome.lower(), {})


def perfis_disponiveis() -> str:
    return ", ".join(PERFIS.keys())


# ─── Perfis de Agentes Ofensivos ─────────────────────────────────────────────

PERFIS_AGENTE = {
    "recon_specialist": {
        "descricao": "Especialista em reconhecimento passivo/ativo — mapeia superfície de ataque antes de qualquer ação invasiva",
        "ferramentas_prioritarias": ["subfinder", "whatweb", "headers", "nmap"],
        "instrucao_cot": (
            "Antes de usar qualquer ferramenta, declare:\n"
            "→ ESCOLHA: [ferramenta] porque [razão técnica vs alternativas]\n"
            "→ PARÂMETROS: [parâmetros-chave] porque [justificativa]\n"
            "→ OBJETIVO: O que espero mapear com este resultado"
        ),
        "restricoes": (
            "Priorize técnicas passivas (subfinder, headers, whatweb) antes de ativas (nmap). "
            "Varreduras ativas só após confirmar permissão de engajamento."
        ),
    },
    "infiltration_specialist": {
        "descricao": "Especialista em validação de vulnerabilidades — confirma achados e propõe vetores de exploração",
        "ferramentas_prioritarias": ["nuclei", "nikto", "gobuster", "bypass_analyst"],
        "instrucao_cot": (
            "Antes de executar qualquer ferramenta ofensiva, avalie:\n"
            "→ HIPÓTESE: Qual vulnerabilidade ou vetor estou validando?\n"
            "→ IMPACTO: Qual o risco se confirmado (CVSS estimado)?\n"
            "→ RISCO OPERACIONAL: Esta ação pode causar disrupção no alvo?"
        ),
        "restricoes": (
            "Toda ação agressiva (nikto, nuclei com tags cve/default-login, gobuster wordlist big) "
            "exige justificativa técnica explícita antes da execução."
        ),
    },
    "reporting_auditor": {
        "descricao": "Auditor de risco — consolida achados, quantifica impacto e produz relatório executivo",
        "ferramentas_prioritarias": ["historico"],
        "instrucao_cot": (
            "Antes de emitir qualquer conclusão:\n"
            "→ EVIDÊNCIA: Os dados coletados suportam esta afirmação?\n"
            "→ SEVERIDADE: Qual CVSS e impacto de negócio real?\n"
            "→ ACIONABILIDADE: A recomendação é implementável pelo time de dev/ops?"
        ),
        "restricoes": (
            "Não execute ferramentas de scan — consolide apenas resultados já coletados. "
            "Toda severidade deve ser justificada com base nos dados, não em suposições."
        ),
    },
}


def obter_perfil_agente(nome: str) -> dict:
    """Retorna o perfil de agente ofensivo pelo nome."""
    return PERFIS_AGENTE.get(nome.lower(), {})


def perfis_agente_disponiveis() -> str:
    return ", ".join(PERFIS_AGENTE.keys())
