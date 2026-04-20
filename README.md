# Offensive AI — Agente OWASP

Agente de IA para auditoria de segurança ofensiva baseado em LangGraph com arquitetura multi-agent.
Combina varredura de rede (Nmap) e análise de headers HTTP (OWASP) em um único fluxo conversacional.

## Arquitetura

```
Você
 └── Supervisor  (roteia a requisição)
      ├── Agente Nmap     → reconhecimento de portas e serviços
      └── Agente Headers  → análise de headers HTTP e conformidade OWASP
```

| Arquivo | Responsabilidade |
|---|---|
| `agente.py` | Entry point — loop de conversa |
| `security.py` | Allowlist de flags nmap e validação de alvos |
| `prompts.py` | Prompts de sistema dos três agentes |
| `terminal.py` | Formatação colorida do output |
| `tools/nmap.py` | Ferramenta `executar_nmap` |
| `tools/headers.py` | Ferramenta `analisar_headers` |
| `agents/nmap.py` | Sub-agente Nmap |
| `agents/headers.py` | Sub-agente Headers |
| `agents/supervisor.py` | Supervisor com memória de sessão |

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/)
- Chave de API do [Google Gemini](https://aistudio.google.com/apikey)

## Instalação

```bash
git clone https://github.com/seu-usuario/offensive-ai.git
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
faz uma varredura de vulnerabilidades nas portas abertas de exemplo.com
verifica se o site exemplo.com tem HSTS configurado
```

## Segurança

O agente opera com allowlist estrita:
- Apenas flags nmap explicitamente permitidas são aceitas
- Scripts NSE limitados a: `vuln`, `default`, `safe`, `discovery`, `http-headers`, `http-title`, `ssl-enum-ciphers`, `banner`
- Alvos validados por regex — apenas domínios e IPs válidos
- Execução isolada em container Docker

> **Aviso:** Use apenas em sistemas que você tem autorização explícita para testar.
