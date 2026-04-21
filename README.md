# QuarkScan

**Agente de IA para reconhecimento e auditoria de segurança ofensiva.**  
Interface conversacional em português — você descreve o objetivo, o agente decide as ferramentas, executa e consolida os resultados.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-ReAct-orange)
![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-4285F4?logo=google&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ubuntu%2022.04-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Visão Geral

QuarkScan é uma plataforma multi-agente onde um **Supervisor LLM** interpreta sua intenção e roteia para agentes especializados, cada um com seu próprio modelo e conjunto de ferramentas. Os resultados são persistidos em SQLite para consulta e comparação histórica.

```
Você: "scan completo em exemplo.com"
       │
       ▼
┌─────────────────────┐
│   Supervisor LLM    │  ← Gemini 2.5 Flash · LangGraph ReAct · MemorySaver
└──────────┬──────────┘
           │ roteia para agentes especializados
     ┌─────┼──────────────────────────────────┐
     ▼     ▼     ▼        ▼       ▼      ▼    ▼
  [nmap] [headers] [gobuster] [nikto] [whatweb] [subfinder] [histórico]
     │       │        │         │        │         │
     └───────┴────────┴─────────┴────────┴─────────┘
                          │
                  ┌───────▼───────┐
                  │  SQLite (DB)  │  ← histórico · comparação · diff entre scans
                  └───────────────┘
```

---

## Funcionalidades

- **7 agentes especializados** — cada um com LLM próprio e domínio específico
- **Supervisor inteligente** — roteia, evita loops, não repete scans já realizados
- **Evasão de WAF/CDN** — perfis de navegador reais (Chrome, Firefox, Safari, Googlebot), delays configuráveis, técnicas de evasão IDS
- **Histórico persistente** — compara dois scans do mesmo alvo e destaca o que mudou
- **Enumeração de subdomínios** — filtra automaticamente os prioritários (api, admin, jenkins, staging...)
- **Segurança de execução** — allowlist de flags Nmap, validação de alvos, scripts NSE restritos
- **Isolamento por sessão** — deduplicação de chamadas por hash de argumentos
- **Container Docker** — ambiente completo e isolado com SecLists incluída

---

## Agentes

| Agente | Ferramenta | Função |
|---|---|---|
| `agente_nmap` | Nmap | Portas, serviços, fingerprint de OS, scripts NSE |
| `agente_headers` | requests | Headers HTTP, cookies, conformidade OWASP |
| `agente_gobuster` | Gobuster + SecLists | Diretórios, arquivos e paths ocultos |
| `agente_nikto` | Nikto | CVEs, misconfigurações de servidor, versões vulneráveis |
| `agente_whatweb` | WhatWeb | CMS, frameworks, bibliotecas, stack completo |
| `agente_subfinder` | Subfinder | Subdomínios via DNS passivo e certificate transparency |
| `agente_historico` | SQLite | Histórico de scans, comparação entre execuções |

---

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) — todas as ferramentas rodam no container
- Chave de API do [Google Gemini](https://aistudio.google.com/apikey) — o modelo é gratuito no tier de desenvolvimento

---

## Instalação

```bash
git clone https://github.com/protonnegativo/QuarkScan.git
cd QuarkScan
cp .env.example .env
```

Edite `.env` e adicione sua chave:

```env
GEMINI_API_KEY=sua_chave_aqui
```

---

## Uso

```bash
chmod +x start_agent.sh
./start_agent.sh
```

O script verifica o Docker, faz o build da imagem e inicia o agente. O banco de dados é persistido em `./data/` no host.

### Exemplos de comandos

```
scan completo em exemplo.com
analisa os headers de exemplo.com
enumera subdomínios de exemplo.com
faz gobuster com wordlist medium em exemplo.com
vulnerabilidades nas portas abertas de exemplo.com
mostra o histórico de scans de exemplo.com
compara os dois últimos nmap de exemplo.com
```

### Evasão de WAF

O agente tenta automaticamente técnicas de evasão quando detecta CDN/WAF (Akamai, Cloudflare). Você também pode ser explícito:

```
nikto em exemplo.com com perfil chrome e evasão
gobuster em exemplo.com com delay de 1s e perfil firefox
```

---

## Estrutura do Projeto

```
QuarkScan/
├── agente.py          # Entry point — loop de conversa
├── prompts.py         # System prompts de todos os agentes
├── security.py        # Allowlist de flags e validação de alvos
├── storage.py         # Persistência SQLite
├── session.py         # Deduplicação de chamadas por sessão
├── profiles.py        # Perfis de navegador para evasão
├── terminal.py        # Formatação colorida do output
├── agents/
│   ├── supervisor.py  # Orquestrador LangGraph com MemorySaver
│   ├── nmap.py
│   ├── headers.py
│   ├── gobuster.py
│   ├── nikto.py
│   ├── whatweb.py
│   ├── subfinder.py
│   └── historico.py
├── tools/             # Wrappers que executam os binários
│   ├── nmap.py
│   ├── headers.py
│   ├── gobuster.py
│   ├── nikto.py
│   ├── whatweb.py
│   ├── subfinder.py
│   └── historico.py
├── Dockerfile
├── start_agent.sh
└── requirements.txt
```

---

## Segurança e Controles

| Controle | Detalhe |
|---|---|
| Flags Nmap | Allowlist explícita — flags não listadas são ignoradas |
| Scripts NSE | Restritos a: `vuln`, `default`, `safe`, `discovery`, `http-headers`, `http-title`, `ssl-enum-ciphers`, `banner` |
| Alvos | Validados por regex — apenas domínios e IPs válidos aceitos |
| Extensões Gobuster | Validadas por regex antes do uso |
| Isolamento | Execução dentro de container Docker |

---

## Aviso Legal

> Este projeto é destinado exclusivamente a fins educacionais e a testes em sistemas **para os quais você possui autorização explícita**.  
> O uso não autorizado contra sistemas de terceiros é ilegal e de responsabilidade exclusiva do usuário.  
> Os autores não se responsabilizam por qualquer uso indevido desta ferramenta.
