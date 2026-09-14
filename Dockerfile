FROM python:3.11-slim

LABEL author="Denilson França"
LABEL description="Automated OWASP Top 10 pentest scanner - Ghost Gear"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    nikto \
    whatweb \
    dnsutils \
    curl \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir sqlmap

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "ghost_gear.py"]
