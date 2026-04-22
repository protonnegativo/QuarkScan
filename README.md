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
┌─────────────────────────────────────────┐
│             Supervisor LLM              │
│  Gemini 2.5 Flash · LangGraph · Memory  │
└─────────────────────────────────────────┘
              │
              ├──▶ agente_nmap       →  Nmap
              ├──▶ agente_headers    →  requests
              ├──▶ agente_gobuster   →  Gobuster + SecLists
              ├──▶ agente_nikto      →  Nikto
              ├──▶ agente_nuclei     →  Nuclei (templates)
              ├──▶ agente_whatweb    →  WhatWeb
              ├──▶ agente_subfinder  →  Subfinder
              └──▶ agente_historico  →  SQLite
                          │
                          ▼
                  ┌───────────────┐
                  │  SQLite (DB)  │  ← histórico · diff entre scans
                  └───────────────┘
```

---

## Funcionalidades

- **8 agentes especializados** — cada um com LLM próprio e domínio específico
- **Supervisor inteligente** — roteia, evita loops, não repete scans já realizados
- **Cache de resultados** — consulta o banco antes de cada scan; evita re-execuções desnecessárias entre sessões
- **Proteção anti-loop** — limite de recursão por agente; erros de quota/API tratados sem crash
- **Evasão de WAF/CDN** — perfis de navegador reais (Chrome, Firefox, Safari, Googlebot), delays configuráveis, técnicas de evasão IDS
- **Histórico persistente** — compara dois scans do mesmo alvo e destaca o que mudou
- **Enumeração de subdomínios** — filtra automaticamente os prioritários (api, admin, jenkins, staging...)
- **Parâmetros completos** — todos os tools expõem os flags relevantes das ferramentas oficiais
- **Segurança de execução** — allowlist de flags Nmap, validação de alvos, scripts NSE restritos
- **Deduplicação por sessão** — evita chamadas duplicadas via hash SHA-256 dos argumentos
- **Container Docker** — ambiente completo e isolado com SecLists e templates Nuclei incluídos

---

## Agentes

| Agente | Ferramenta | Função |
|---|---|---|
| `agente_nmap` | Nmap | Portas, serviços, fingerprint de OS, scripts NSE |
| `agente_headers` | requests | Headers HTTP, cookies, conformidade OWASP |
| `agente_gobuster` | Gobuster + SecLists | Diretórios, arquivos e paths ocultos |
| `agente_nikto` | Nikto | CVEs, misconfigurações de servidor, versões vulneráveis |
| `agente_nuclei` | Nuclei | CVEs indexados, exposições, defaults de login, templates ProjectDiscovery |
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
nuclei em exemplo.com focando em CVEs críticos
mostra o histórico de scans de exemplo.com
compara os dois últimos nmap de exemplo.com
```

### Cache de resultados

O agente consulta o banco antes de executar cada scan. Se houver resultado recente, ele é retornado imediatamente. Para forçar um novo scan, basta pedir explicitamente:

```
refaz o nmap em exemplo.com com resultado atualizado
```

### Evasão de WAF

O agente tenta automaticamente técnicas de evasão quando detecta CDN/WAF. Você também pode ser explícito:

```
nikto em exemplo.com com perfil chrome e evasão ids
gobuster em exemplo.com http com delay de 1s e perfil firefox
nuclei em exemplo.com usando proxy http://127.0.0.1:8080
```

---

## Estrutura do Projeto

```
QuarkScan/
├── agente.py          # Entry point — loop de conversa
├── prompts.py         # System prompts de todos os agentes
├── security.py        # Allowlist de flags Nmap e validação de alvos
├── storage.py         # Persistência SQLite + cache de resultados
├── session.py         # Deduplicação de chamadas por sessão (SHA-256)
├── profiles.py        # Perfis de navegador para evasão WAF
├── terminal.py        # Formatação colorida do output
├── agents/
│   ├── base.py        # invocar() com recursion_limit e tratamento de erros
│   ├── supervisor.py  # Orquestrador LangGraph com MemorySaver
│   ├── nmap.py
│   ├── headers.py
│   ├── gobuster.py
│   ├── nikto.py
│   ├── nuclei.py
│   ├── whatweb.py
│   ├── subfinder.py
│   └── historico.py
├── tools/             # Wrappers que executam os binários
│   ├── nmap.py
│   ├── headers.py
│   ├── gobuster.py
│   ├── nikto.py
│   ├── nuclei.py
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
| Flags Nmap | Allowlist explícita — inclui `-sS/sT/sU/sV/sN/sF/sX`, `--top-ports`, `--min-rate`, `-PE/-PS/-PA` e outros |
| Scripts NSE | Restritos a: `vuln`, `default`, `safe`, `discovery`, `http-headers`, `http-title`, `ssl-enum-ciphers`, `ssl-cert`, `banner`, `http-methods`, `ftp-anon`, `ssh-hostkey`, `smb-vuln-ms17-010` e outros |
| Alvos | Validados por regex — apenas domínios e IPs válidos aceitos |
| Extensões Gobuster | Validadas por regex antes do uso |
| Status codes / comprimento | Whitelist e blacklist de respostas configuráveis |
| Cache de resultados | TTL por ferramenta (12h–72h) — evita re-scans automáticos |
| Deduplicação | Hash SHA-256 dos argumentos por sessão |
| Anti-loop | Limite de 10 iterações por agente especialista |
| Isolamento | Execução dentro de container Docker |

---

## To Do — Roadmap para Pentest Autônomo

### Módulos de Reconhecimento (inspirados no Sophia)

- [ ] **agente_osint** — Certificate Transparency (crt.sh), Shodan, VirusTotal, WHOIS, ASN lookup, Google Dorks automatizados. Hoje o subfinder cobre só DNS passivo; OSINT amplia a superfície de ataque antes de qualquer scan ativo
- [ ] **agente_ssl** — Análise de certificados TLS, ciphers fracos, BEAST/POODLE/Heartbleed, expiração. Wraps: `sslscan`, `testssl.sh`
- [ ] **agente_cloud** — Detecção de buckets S3/Azure Blob/GCP expostos, endpoints de metadata (169.254.169.254), headers de provider. Wraps: `cloudenum`, `s3scanner`
- [ ] **Múltiplos enumeradores de subdomínio** — Adicionar `amass`, `assetfinder` e `findomain` ao `agente_subfinder`, com deduplicação e merge automático dos resultados
- [ ] **agente_dns** — Zone transfer, DNSSEC check, registros SPF/DMARC/DKIM mal configurados, wildcard DNS. Wraps: `dnsx`, `dnsrecon`

### Capacidades de Exploração e Pós-Reconhecimento

- [ ] **agente_api** — Descoberta de endpoints REST/GraphQL, fuzz de parâmetros, detecção de CORS aberto, auth bypass em APIs. Wraps: `ffuf`, `arjun`
- [ ] **agente_exploit** — Dado o output do Nuclei/Nmap, o supervisor sugere e confirma com o usuário antes de tentar exploits conhecidos via `searchsploit` / Metasploit RPC
- [ ] **agente_bruteforce** — Brute-force de credenciais em serviços descobertos (SSH, FTP, RDP, SMB, HTTP Basic). Wraps: `hydra`, `medusa`
- [ ] **agente_screenshot** — Captura automática de screenshots de todos os serviços HTTP/HTTPS ativos para triagem visual. Wraps: `gowitness`, `eyewitness`

### Inteligência e Autonomia

- [ ] **Pipeline de fases** — Modo autônomo sequencial: `recon → enum → vuln_scan → exploração → report`, com confirmação do usuário antes de cada fase destrutiva
- [ ] **Modo aggressivo / lightweight** — Flag no chat para controlar intensidade (threads, timeout, técnicas usadas) sem editar código
- [ ] **Correlação cruzada de resultados** — O supervisor cruza o output de todos os agentes para identificar padrões: portas abertas + serviço vulnerável + endpoint exposto = vetor de ataque priorizado
- [ ] **Score de risco por alvo** — Ao fim de um scan completo, gerar um score (Crítico/Alto/Médio/Baixo) com base nas descobertas, similar ao CVSS mas contextualizado
- [ ] **Replay de sessão** — Recarregar uma sessão anterior pelo ID e continuar de onde parou, sem repetir o que já foi scaneado

### Reporting e Output

- [ ] **Geração de relatório** — Exportar o resultado consolidado em Markdown e HTML com sumário executivo, tabela de vulnerabilidades, evidências e recomendações
- [ ] **agente_diff** — Comparação automática entre dois relatórios do mesmo alvo em datas diferentes, destacando o que surgiu, o que foi corrigido e o que piorou (hoje o histórico existe, mas a análise de diff é manual)
- [ ] **Notificação** — Webhook/Telegram quando um scan longo terminar ou quando uma vulnerabilidade crítica for encontrada

### Infraestrutura

- [ ] **Dry run** — Modo que imprime todos os comandos que seriam executados sem rodar nada, para revisão antes de um engajamento real
- [ ] **Config por engajamento** — Arquivo `.conf` por alvo com scope, exclusões, wordlists preferidas e TTL de cache customizado
- [ ] **Rate limiting configurável por alvo** — Perfis de velocidade salvos (stealth, normal, agressivo) que o supervisor aplica automaticamente baseado no tipo de alvo detectado

---

## Aviso Legal

> Este projeto é destinado exclusivamente a fins educacionais e a testes em sistemas **para os quais você possui autorização explícita**.  
> O uso não autorizado contra sistemas de terceiros é ilegal e de responsabilidade exclusiva do usuário.  
> Os autores não se responsabilizam por qualquer uso indevido desta ferramenta.
