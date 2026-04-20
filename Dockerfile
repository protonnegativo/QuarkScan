# Usa uma imagem oficial e leve do Ubuntu
FROM ubuntu:22.04

# Evita perguntas interativas durante a instalação
ENV DEBIAN_FRONTEND=noninteractive

# Atualiza e instala ferramentas DO SISTEMA (Ubuntu)
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    whatweb \
    gobuster \
    dirb \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos do seu projeto para dentro da caixa
COPY . .

# Instala as dependências Python
RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["python3", "agente.py"]