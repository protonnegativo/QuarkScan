#!/bin/bash

# Cores para o terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # Sem cor

echo -e "${BLUE}[*] Verificando serviço do Docker...${NC}"
if ! systemctl is-active --quiet docker; then
    echo -e "${BLUE}[!] Docker está desligado. Ligando...${NC}"
    sudo systemctl start docker
fi

echo -e "${BLUE}[*] Atualizando a 'fotografia' do agente (Build)...${NC}"
# O --quiet serve para não encher sua tela de logs de instalação
docker build -q -t ia-nmap-agent . > /dev/null 2>&1

echo -e "${GREEN}[+] Iniciando Agente de IA Isolado...${NC}"
echo -e "${GREEN}------------------------------------------${NC}"

docker run -it --rm --env-file .env ia-nmap-agent