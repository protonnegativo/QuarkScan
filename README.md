# Offensive AI — Agente OWASP

Agente de IA para auditoria de segurança ofensiva baseado em LangGraph com arquitetura multi-agent.
Um supervisor inteligente roteia cada requisição para o especialista correto e consolida os resultados.

## Arquitetura

```
Você
 └── Supervisor  (roteia e consolida)
      ├── Agente Nmap       → reconhecimento de portas e serviços
      ├── Agente Headers    → análise de headers HTTP e conformidade OWASP
      ├── Agente Gobuster   → enumeração de diretórios e arquivos ocultos
      ├── Agente Nikto      → varredura de vulnerabilidades e CVEs
      └── Agente WhatWeb    → fingerprinting de stack tecnológico
```

| Arquivo | Responsabilidade |
|---|---|
| `agente.py` | Entry point — loop de conversa |
| `security.py` | Allowlist de flags e validação de alvos |
| `prompts.py` | Prompts de sistema de todos os agentes |
| `terminal.py` | Formatação colorida do output |
| `tools/` | Ferramentas que executam os binários do sistema |
| `agents/` | Sub-agentes LangGraph com LLM próprio |
| `agents/supervisor.py` | Supervisor com memória de sessão |

## Ferramentas

| Ferramenta | Função | Wordlists / Opções |
|---|---|---|
| **Nmap** | Rede, portas, serviços, fingerprint OS | flags via allowlist |
| **Headers** | Headers HTTP, cookies, OWASP | — |
| **Gobuster** | Diretórios e arquivos ocultos | small / common / medium / big (SecLists) |
| **Nikto** | CVEs, misconfigurações de servidor | — |
| **WhatWeb** | CMS, frameworks, bibliotecas, stack | agressividade 1–3 |

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/)
- Chave de API do [Google Gemini](https://aistudio.google.com/apikey)

## Instalação

```bash
git clone https://github.com/protonnegativo/offensive-ai.git
cd offensive-ai

cp .env.example .env
# Edite .env e adicione sua GEMINI_API_KEY
```

## Uso

```bash
chmod +x start_agent.sh
./start_agent.sh
```

### Exemplos de comandos

```
scan completo no exemplo.com
analisa os headers de exemplo.com
enumera diretórios de exemplo.com com wordlist medium
faz varredura de vulnerabilidades em exemplo.com
identifica o stack tecnológico de exemplo.com
verifica se o site exemplo.com tem HSTS configurado
```

## Segurança

O agente opera com controles estritos:
- Flags Nmap limitadas a uma allowlist explícita
- Scripts NSE permitidos: `vuln`, `default`, `safe`, `discovery`, `http-headers`, `http-title`, `ssl-enum-ciphers`, `banner`
- Alvos validados por regex — apenas domínios e IPs válidos
- Extensões do Gobuster validadas por regex
- Execução isolada em container Docker (ubuntu:22.04)

> **Aviso:** Use apenas em sistemas que você tem autorização explícita para testar.
