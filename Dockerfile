FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    whatweb \
    gobuster \
    curl \
    unzip \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN SUBFINDER_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') && \
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_amd64.zip" \
         -o /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
         -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

RUN nuclei -update-templates -silent 2>/dev/null || true

RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
         -o /usr/share/seclists/Discovery/Web-Content/common.txt && \
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
         -o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt && \
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" \
         -o /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

WORKDIR /app

COPY . .

RUN pip3 install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python3", "agente.py"]
