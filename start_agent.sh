#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Modo de execução ────────────────────────────────────────────────────────
MODE="agent"
WEBUI_PORT=5000

for arg in "$@"; do
  case $arg in
    --webui)    MODE="webui" ;;
    --port=*)   WEBUI_PORT="${arg#*=}" ;;
  esac
done

# ── Verifica .env ───────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo -e "\033[0;31m[!] Arquivo .env não encontrado. Copie .env.example e preencha a GEMINI_API_KEY.\033[0m"
    exit 1
fi

# ── Web UI (roda localmente, sem Docker) ────────────────────────────────────
if [ "$MODE" = "webui" ]; then
    echo -e "${BLUE}[*] Verificando serviço do Docker...${NC}"
    if ! systemctl is-active --quiet docker; then
        echo -e "${BLUE}[!] Docker está desligado. Ligando...${NC}"
        sudo systemctl start docker
    fi

    echo -e "${BLUE}[*] Atualizando imagem (Build)...${NC}"
    if ! docker build -t quarkscan . ; then
        echo -e "\033[0;31m[!] Build falhou.\033[0m"
        exit 1
    fi

    echo -e "${GREEN}[+] Web UI disponível em: http://localhost:${WEBUI_PORT}${NC}"
    echo -e "${GREEN}------------------------------------------${NC}"

    mkdir -p data
    docker run -it --rm \
        --env-file .env \
        -v "$(pwd)/data:/app/data" \
        -p ${WEBUI_PORT}:5000 \
        quarkscan \
        python3 webui.py
    exit 0
fi

# ── Agente (Docker) ─────────────────────────────────────────────────────────
echo -e "${BLUE}[*] Verificando serviço do Docker...${NC}"
if ! systemctl is-active --quiet docker; then
    echo -e "${BLUE}[!] Docker está desligado. Ligando...${NC}"
    sudo systemctl start docker
fi

echo -e "${BLUE}[*] Atualizando a 'fotografia' do agente (Build)...${NC}"
if ! docker build -t quarkscan . ; then
    echo -e "\033[0;31m[!] Build falhou. Corrija os erros acima antes de continuar.\033[0m"
    exit 1
fi

echo -e "${GREEN}[+] Iniciando QuarkScan...${NC}"
echo -e "${YELLOW}[*] Dica: ./start_agent.sh --webui  → abre o dashboard no navegador${NC}"
echo -e "${GREEN}------------------------------------------${NC}"

mkdir -p data
docker run -it --rm \
    --env-file .env \
    -v "$(pwd)/data:/app/data" \
    -p ${WEBUI_PORT}:5000 \
    quarkscan
