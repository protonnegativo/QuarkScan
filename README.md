# QuarkScan

**Agente de IA para reconhecimento e auditoria de segurança ofensiva.**  
Interface conversacional em português — você descreve o objetivo, o agente decide as ferramentas, executa e consolida os resultados.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-orange)
![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-4285F4?logo=google&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ubuntu%2022.04-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Visão Geral

QuarkScan é uma plataforma multi-agente onde um **Supervisor LLM** interpreta sua intenção e roteia para agentes especializados, cada um com seu próprio modelo e conjunto de ferramentas. Os resultados são persistidos em SQLite com memória de longo prazo entre engajamentos.

```
Você: "pipeline em exemplo.com"
              │
              ▼
┌─────────────────────────────────────────┐
│         Supervisor LLM (LangGraph)      │
│    Gemini API · StateGraph · Memory     │
└─────────────────────────────────────────┘
              │
              ├──▶ agente_subfinder   →  Subfinder  ──▶ fallback DNS brute-force
              ├──▶ agente_nmap        →  Nmap
              ├──▶ agente_headers     →  requests
              ├──▶ agente_gobuster    →  Gobuster + SecLists
              ├──▶ agente_nikto       →  Nikto
              ├──▶ agente_nuclei      →  Nuclei (templates)
              ├──▶ agente_whatweb     →  WhatWeb
              ├──▶ agente_historico   →  SQLite
              └──▶ bypass_analyst     →  Análise de evasão WAF
                          │
                          ▼
              ┌───────────────────────┐
              │  ValidationGuardrails │  ← Regex + LLM semântico + rate limit
              └───────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │  SQLite (DB)  │  ← resultados · vulns · memória de subdomínios
                  └───────────────┘
```

---

## Funcionalidades

- **9 agentes especializados** — cada um com LLM próprio e domínio específico
- **Supervisor inteligente** — roteia, evita loops, não repete scans já realizados
- **Pipeline LangGraph (StateGraph)** — grafo de estado com fallback automático: se subfinder retornar zero resultados, aciona DNS brute-force automaticamente antes de prosseguir
- **Fases destrutivas com gate de confirmação** — recon passivo e ativo sem confirmação; enumeração e vuln analysis exigem aprovação interativa
- **Validation Guardrails** — camada universal de segurança em todos os tools: regex (9 padrões de injeção) + análise semântica LLM + rate limiting por tool/alvo
- **Protocolo GO/NO-GO** — supervisor avalia autorização, completude do recon passivo e risco operacional antes de qualquer scan agressivo
- **Chain of Thought obrigatório** — todos os agentes justificam tecnicamente cada escolha de ferramenta e parâmetro antes de executar (`→ ESCOLHA / → OBJETIVO`)
- **Perfis de operador ofensivo** — três papéis com instruções e restrições distintas: `recon_specialist`, `infiltration_specialist` e `reporting_auditor`
- **Tool Self-Correction** — quando uma ferramenta retorna exit code ≠ 0, a mensagem de erro inclui dica de correção estruturada para o agente ReAct reparar os parâmetros e reinvocar autonomamente
- **Progress Monitoring** — heartbeat a cada 30–60s em execuções longas (nmap -p-, nuclei, gobuster); mostra tempo decorrido/total em tempo real
- **Smart Truncation** — outputs grandes são cortados 65% cabeça + 35% cauda para preservar início (contexto) e fim (achados/conclusões) em vez de truncar linearmente
- **Métricas de execução** — cada chamada de ferramenta registra exit_code, duração e taxa de sucesso no SQLite; agentes aprendem quais ferramentas são instáveis no alvo atual
- **Memória de longo prazo** — vulnerabilidades descobertas e subdomínios scaneados persistem entre sessões; evita rescans redundantes e economiza API
- **Bypass Analyst** — agente Red Team que revisa payloads e propõe variações para evadir assinaturas de WAF (ModSecurity CRS, Cloudflare, AWS WAF, Imperva, F5)
- **Modelo configurável** — troca o modelo de qualquer agente via env var; cada agente pode usar um modelo diferente
- **Cache de resultados** — TTL por ferramenta (12h–72h); evita re-execuções desnecessárias
- **Evasão de WAF/CDN** — perfis de navegador reais (Chrome, Firefox, Safari, Googlebot), delays configuráveis, técnicas de evasão IDS
- **Histórico persistente** — compara dois scans do mesmo alvo e destaca o que mudou
- **Enumeração de subdomínios** — filtra automaticamente os prioritários (api, admin, jenkins, staging...)
- **Segurança de execução** — allowlist de flags Nmap, validação de alvos, scripts NSE restritos
- **Deduplicação por sessão** — evita chamadas duplicadas via hash SHA-256 dos argumentos
- **Container Docker** — ambiente completo e isolado com SecLists e templates Nuclei incluídos

---

## Agentes

| Agente | Ferramenta | Função |
|---|---|---|
| `agente_subfinder` | Subfinder | Subdomínios via DNS passivo e certificate transparency |
| `agente_nmap` | Nmap | Portas, serviços, fingerprint de OS, scripts NSE |
| `agente_headers` | requests | Headers HTTP, cookies, conformidade OWASP |
| `agente_gobuster` | Gobuster + SecLists | Diretórios, arquivos e paths ocultos |
| `agente_nikto` | Nikto | CVEs, misconfigurações de servidor, versões vulneráveis |
| `agente_nuclei` | Nuclei | CVEs indexados, exposições, defaults de login, templates ProjectDiscovery |
| `agente_whatweb` | WhatWeb | CMS, frameworks, bibliotecas, stack completo |
| `agente_historico` | SQLite | Histórico de scans, comparação entre execuções |
| `bypass_analyst` | LLM (Red Team) | Análise de payloads e geração de variações de bypass WAF |

---

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) — todas as ferramentas rodam no container
- Chave de API do [Google Gemini](https://aistudio.google.com/apikey) — `gemini-2.5-flash` é gratuito no tier de desenvolvimento

> **Permissão no Docker (Linux):** após instalar o Docker, adicione seu usuário ao grupo `docker` para evitar o erro `permission denied` no socket:
> ```bash
> sudo usermod -aG docker $USER
> newgrp docker
> ```
> Se o `newgrp` não funcionar, faça logout/login para que o grupo seja aplicado.

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

# Modelo padrão para todos os agentes (opcional — default: gemini-2.5-flash)
# GEMINI_MODEL=gemini-2.5-pro

# Override por agente — útil para usar Pro no supervisor e Flash nos demais
# GEMINI_MODEL_SUPERVISOR=gemini-2.5-pro
# GEMINI_MODEL_NMAP=gemini-2.5-flash
# GEMINI_MODEL_BYPASS_ANALYST=gemini-2.5-flash

# Exibe o output bruto das ferramentas antes do LLM processar (opcional)
# QUARKSCAN_RAW=1
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
analisa o bypass deste payload XSS: <script>alert(1)</script>
```

### Cache de resultados

O agente consulta o banco antes de executar cada scan. Se houver resultado recente, ele é retornado imediatamente. Para forçar um novo scan, basta pedir explicitamente:

```
refaz o nmap em exemplo.com com resultado atualizado
```

### Output bruto das ferramentas

Por padrão, o output das ferramentas passa pelo LLM antes de chegar ao terminal. Para ver o output bruto de cada ferramenta imediatamente após a execução — antes de qualquer interpretação — ative a variável de ambiente `QUARKSCAN_RAW`:

```bash
QUARKSCAN_RAW=1 ./start_agent.sh
```

Com a flag ativa, o terminal exibe o output bruto entre marcadores `[RAW ferramenta]` / `[/RAW]` logo após a execução do comando, seguido do output formatado pelo LLM normalmente.

---

### Web UI — Dashboard de Scans

Visualize todos os scans, compare output bruto vs análise da IA e acompanhe vulnerabilidades por alvo no navegador:

```bash
./start_agent.sh --webui
# Abre em: http://localhost:5000
```

Porta customizada:
```bash
./start_agent.sh --webui --port=8080
```

O dashboard oferece:
- **Todos os Scans** — lista paginada com filtro por alvo e ferramenta
- **Output Bruto vs Análise IA** — três abas por scan: Resultado, Output Bruto (exato da ferramenta) e Análise IA
- **Vulnerabilidades** — tabela por alvo com severidade, status e histórico temporal
- **Stats** — totais de scans, alvos e vulnerabilidades no topo

> A Web UI lê o mesmo banco `data/resultados.db` usado pelo agente — não requer Docker, apenas `flask` instalado (`pip3 install flask`).

---

### Pipeline autônomo (LangGraph StateGraph)

Execute todas as fases de reconhecimento em sequência com um único comando. O pipeline é construído como um **grafo de estado** com fallback automático e checkpointing.

```
pipeline em exemplo.com
modo autônomo em exemplo.com
pentest completo em exemplo.com
```

Fases executadas em ordem:

| Fase | Agentes | Confirmação | Fallback |
|---|---|---|---|
| Reconhecimento Passivo | subfinder | não | DNS brute-force se vazio |
| Reconhecimento Ativo | nmap, whatweb, headers | não | — |
| Enumeração | gobuster, nikto | **sim** | — |
| Análise de Vulnerabilidades | nuclei | **sim** | — |
| Relatório consolidado | supervisor (sumário via LLM) | — | — |

**Fallback automático:** se o subfinder não encontrar subdomínios, o pipeline não para — aciona automaticamente um DNS brute-force antes de prosseguir para a Fase 2.

Para usar o pipeline baseado em StateGraph (recomendado), edite `agente.py` e substitua `executar_pipeline` por `executar_pipeline_graph`.

### Evasão de WAF

O agente tenta automaticamente técnicas de evasão quando detecta CDN/WAF. Você também pode ser explícito:

```
nikto em exemplo.com com perfil chrome e evasão ids
gobuster em exemplo.com http com delay de 1s e perfil firefox
nuclei em exemplo.com usando proxy http://127.0.0.1:8080
```

### Bypass Analyst

O agente `bypass_analyst` analisa payloads de exploit gerados durante o pentest e propõe variações para evadir assinaturas de WAF conhecidas:

```
analisa o bypass deste payload SQLi: ' OR 1=1--
revisa o payload XSS para bypass de cloudflare: <script>alert(document.cookie)</script>
bypass analyst no payload de SSTI: {{7*7}}
```

O agente retorna variações ordenadas por probabilidade de evasão, indicando quais WAFs cada variação consegue bypassar. Os resultados são cacheados por 7 dias para evitar chamadas desnecessárias ao LLM.

Tipos suportados: `sqli`, `xss`, `lfi`, `rce`, `ssti`, `xxe`, `ssrf`

---

## Segurança e Controles

| Controle | Detalhe |
|---|---|
| **Validation Guardrails** | Camada universal em todos os tools: 9 padrões regex (metacaracteres, path traversal, backtick, cmd substitution, null bytes, etc.) + análise semântica LLM + rate limiting 5 calls/60s por tool/alvo |
| **GO/NO-GO Adversarial Review** | Supervisor avalia autorização, completude do recon passivo e risco operacional antes de scans agressivos (nikto, nuclei, gobuster ≥medium); downgrade automático para versão passiva se condições não forem satisfeitas |
| Flags Nmap | Allowlist explícita — inclui `-sS/sT/sU/sV/sN/sF/sX`, `--top-ports`, `--min-rate`, `-PE/-PS/-PA` e outros |
| Scripts NSE | Restritos a: `vuln`, `default`, `safe`, `discovery`, `http-headers`, `ssl-enum-ciphers`, `ssl-cert`, `banner`, `http-methods`, `ftp-anon`, `ssh-hostkey`, `smb-vuln-ms17-010` e outros |
| Alvos | Validados por regex — apenas domínios e IPs válidos aceitos |
| Extensões Gobuster | Validadas por regex antes do uso |
| Cache de resultados | TTL por ferramenta (12h–72h) — evita re-scans automáticos |
| Memória de longo prazo | Vulnerabilidades indexadas por `(alvo, subdomínio, identificador)` — deduplicação automática entre sessões |
| Deduplicação | Hash SHA-256 dos argumentos por sessão |
| Anti-loop | Limite de 10 iterações por agente especialista |
| Isolamento | Execução dentro de container Docker |

---

## Estrutura do Projeto

```
QuarkScan/
├── agente.py            # Entry point — loop de conversa + inicialização de guardrails
├── pipeline.py          # Pipeline sequencial legado (fases com confirmação)
├── pipeline_graph.py    # Pipeline LangGraph StateGraph com fallback e checkpointing
├── llm.py               # Resolução de modelo via env var (GEMINI_MODEL_*)
├── prompts.py           # System prompts de todos os agentes
├── security.py          # Allowlist Nmap · validação de alvos · ValidationGuardrails
├── storage.py           # SQLite: resultados · cache TTL · memória de vulns/subdomínios · métricas de execução
├── session.py           # Deduplicação de chamadas por sessão (SHA-256)
├── profiles.py          # Perfis de navegador (Chrome/Firefox/Safari/Googlebot) + PERFIS_AGENTE (recon/infiltration/reporting)
├── terminal.py          # Formatação colorida · executar_com_monitoramento() · truncar_inteligente()
├── agents/
│   ├── base.py          # invocar() com recursion_limit e tratamento de erros
│   ├── supervisor.py    # Orquestrador LangGraph com MemorySaver
│   ├── bypass_analyst.py  # Agente Red Team para evasão de WAF
│   ├── nmap.py
│   ├── headers.py
│   ├── gobuster.py
│   ├── nikto.py
│   ├── nuclei.py
│   ├── whatweb.py
│   ├── subfinder.py
│   └── historico.py
├── tools/               # Wrappers com guardrail_check() · monitoramento · self-correction hints
│   ├── bypass.py        # Análise de bypass WAF com cache 7 dias
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

## To Do — Roadmap para Pentest Autônomo

As seções seguem as fases de um engajamento real. Itens dentro de cada fase estão ordenados pela ordem natural de execução.

### Fase 0 — Pré-Engajamento

*Itens que definem como o teste será conduzido antes de qualquer ação no alvo.*

| Item | Descrição |
|---|---|
| **Dry run** | Imprime todos os comandos que seriam executados sem rodar nada, para revisão antes de um engajamento real |
| **Config por engajamento** | Arquivo `.conf` por alvo com scope, exclusões, wordlists preferidas e TTL de cache customizado |
| **Rate limiting por alvo** | Perfis de velocidade salvos (stealth, normal, agressivo) aplicados automaticamente pelo supervisor conforme o tipo de alvo detectado |

### Fase 1 — Reconhecimento Passivo

*Nenhum contato direto com o alvo. Apenas consulta de fontes públicas e APIs de terceiros.*

| Item | Descrição | Ferramentas |
|---|---|---|
| **agente_osint** | Certificate Transparency, Shodan, VirusTotal, WHOIS, ASN lookup, Google Dorks. Amplia a superfície antes de qualquer contato com o alvo | `crt.sh`, `shodan`, `virustotal` |
| **agente_github_recon** | Secrets, credenciais e endpoints vazados em repositórios públicos. Fonte de alto impacto frequentemente ignorada | `trufflehog`, `gitleaks`, `github-search` |
| **Enumeradores de subdomínio (passivo)** | Consulta apenas APIs passivas (Shodan, crt.sh, VirusTotal). ~~amass~~ descontinuado — substituído por `chaos`. Resolução ativa pertence à Fase 2 | `assetfinder`, `findomain`, `chaos` |

### Fase 2 — Reconhecimento Ativo

*Contato direto com o alvo, mas não intrusivo. Base para calibrar todas as fases seguintes.*

| Item | Descrição | Ferramentas |
|---|---|---|
| **agente_waf** | Detecta WAF/CDN antes de qualquer scan para ajustar a estratégia de evasão. Hoje a evasão é reativa; saber o WAF primeiro muda a abordagem inteira | `wafw00f` |
| **Resolução ativa de subdomínios** | Resolve e valida candidatos da Fase 1 via brute-force de permutações. É ativo porque envia milhares de queries ao DNS do alvo | `puredns` |
| **agente_dns** | Zone transfer, DNSSEC, SPF/DMARC/DKIM mal configurados, wildcard DNS, open relay SMTP | `dnsx`, `dnsrecon` |
| **agente_ssl** | Ciphers fracos, BEAST/POODLE/Heartbleed, expiração de certificado. Output estruturado para relatório formal — Nuclei já cobre checks básicos via templates | `testssl.sh` |
| **agente_cloud** | Buckets S3/Azure Blob/GCP expostos, endpoints de metadata (169.254.169.254), headers de cloud provider | `cloudenum`, `s3scanner` |

### Fase 3 — Enumeração

*Mapeamento detalhado da superfície de ataque. Executado após o recon estabelecer os alvos prioritários.*

| Item | Descrição | Ferramentas |
|---|---|---|
| **agente_crawler** | Spider inteligente de links e formulários. Descobre a superfície real antes do Gobuster, que é força bruta cega | `katana`, `hakrawler` |
| **agente_js** | Analisa artefatos JS já coletados pelo crawler — sem nova interação com o alvo. Extrai endpoints ocultos, secrets e tokens em arquivos estáticos | `linkfinder`, `secretfinder`, `subjs` |
| **agente_screenshot** | Screenshots de todos os serviços HTTP/HTTPS ativos para triagem visual de alvos prioritários | `gowitness`, `eyewitness` |
| **agente_cms** | Scan completo de WordPress (plugins/temas vulneráveis, usuários enumeráveis, xmlrpc, senhas fracas), Joomla e Drupal. WordPress representa ~40% da web — prioridade alta | `wpscan`, `droopescan`, `cmseek` |
| **agente_api** | Discovery passivo: endpoints REST/GraphQL via `arjun`, introspection GraphQL, detecção de CORS aberto. Sem fuzzing agressivo — ffuf pertence à Fase 5 | `arjun` |
| **agente_smb** | Enumeração read-only: shares, sessões nulas, usuários. Sem autenticação ou coleta de hashes — crackmapexec pertence à Fase 5 | `enum4linux-ng`, `smbclient` |

### Fase 4 — Análise de Vulnerabilidades

*Consolidação e priorização do que foi descoberto nas fases anteriores.*

| Item | Descrição |
|---|---|
| **Correlação cruzada** | Supervisor cruza o output de todos os agentes: porta aberta + serviço vulnerável + endpoint exposto = vetor de ataque priorizado |
| **Score de risco** | Score Crítico/Alto/Médio/Baixo ao fim de um scan completo, contextualizado pelo ambiente (web, infra, cloud) |

### Fase 5 — Exploração

*Requer confirmação explícita do usuário antes de cada ação. Log de auditoria obrigatório.*

| Item | Descrição | Ferramentas |
|---|---|---|
| **agente_exploit** | Supervisor sugere e confirma com o usuário antes de tentar exploits baseados no output do Nuclei/Nmap | `searchsploit`, Metasploit RPC |
| **agente_sqli** | SQL injection em parâmetros e formulários descobertos pelo crawler/gobuster | `sqlmap` |
| **agente_bruteforce** | Brute-force de credenciais em serviços (SSH, FTP, RDP, HTTP Basic) | `hydra`, `medusa` |
| **Fuzzing agressivo de API** | ffuf em modo brute-force de rotas sobre endpoints do `agente_api` (Fase 3). Separado por risco de lockout e trigger de IPS | `ffuf` |
| **Autenticação e relay SMB** | pass-pol, login attempts e relay NTLMv2 sobre alvos do `agente_smb` (Fase 3). Separado pelo mesmo motivo | `crackmapexec` |

### Automação e Inteligência

*Funcionalidades que elevam o agente de ferramenta para plataforma autônoma.*

| Item | Descrição |
|---|---|
| ~~**Pipeline de fases**~~ | ✓ Implementado — `pipeline em <alvo>` |
| ~~**Validation Guardrails**~~ | ✓ Implementado — Regex + LLM semântico + rate limiting em todos os tools |
| ~~**Memória de alvo persistente**~~ | ✓ Implementado — tabelas `vulnerabilidades` + `subdominios_memoria` com deduplicação automática |
| ~~**Fallback de recon**~~ | ✓ Implementado — subfinder vazio → DNS brute-force automático no StateGraph |
| ~~**Bypass Analyst**~~ | ✓ Implementado — agente Red Team para evasão de assinaturas WAF |
| **Suporte a múltiplos provedores de IA** | Abstrair o LLM para suportar OpenAI (GPT-4o), Anthropic (Claude), Ollama (local) e Groq além do Gemini. Cada agente poderia usar um provedor diferente via env var — ex: `NMAP_LLM_PROVIDER=ollama` para rodar offline |
| **Modo agressivo / lightweight** | Flag no chat para controlar intensidade (threads, timeout, técnicas) sem editar código |
| **Replay de sessão** | Recarregar sessão anterior pelo ID e continuar de onde parou, sem repetir o que já foi scaneado |
| **Modo MCP server** | Expor o QuarkScan como MCP server para integração em pipelines maiores via outros agentes |

### Fase 6 — Interface Web Interativa

*Dashboard visual para auditoria de scans, comparação raw vs IA e tracking de vulnerabilidades.*

| Item | Descrição |
|---|---|
| ~~**Dashboard Web**~~ | ✓ Implementado — `./start_agent.sh --webui` → `http://localhost:5000` |
| ~~**Output Bruto separado**~~ | ✓ Implementado — coluna `raw_output` no banco; todos os tools salvam stdout bruto |
| ~~**Separação Raw × Análise IA**~~ | ✓ Implementado — três abas por scan: Resultado / Output Bruto / Análise IA |
| ~~**Histórico visual por alvo**~~ | ✓ Implementado — sidebar com alvos, filtro por ferramenta, paginação |
| ~~**Vulnerabilidades por alvo**~~ | ✓ Implementado — aba dedicada com severidade, status e histórico temporal |
| **Re-análise batch com IA** | Selecionar múltiplos outputs e rodar LLM em lote — economiza tokens vs análise por scan |
| **Organização por Projetos** | Agrupar alvos em projetos/engajamentos (ex: "Pentest ClienteX"); exportar relatório do projeto |
| **Execução de scans pela UI** | Disparar scans diretamente pelo browser sem precisar do terminal |

### Reporting

| Item | Descrição |
|---|---|
| **agente_report com LLM** | LLM redige o sumário executivo automaticamente com descobertas priorizadas, exportando em Markdown e HTML com tabela de vulnerabilidades e evidências |
| **agente_diff** | Comparação automática entre relatórios do mesmo alvo em datas diferentes: o que surgiu, foi corrigido e o que piorou |
| **Notificação** | Webhook/Telegram ao término de scan longo ou quando vulnerabilidade crítica for encontrada |

---

## Aviso Legal

> Este projeto é destinado exclusivamente a fins educacionais e a testes em sistemas **para os quais você possui autorização explícita**.  
> O uso não autorizado contra sistemas de terceiros é ilegal e de responsabilidade exclusiva do usuário.  
> Os autores não se responsabilizam por qualquer uso indevido desta ferramenta.
