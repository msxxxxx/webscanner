FROM python:3.13-slim

# Системные зависимости: nmap, git, wget, unzip для установки сканеров
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    wget \
    unzip \
    curl \
    ca-certificates \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python-зависимости отдельным слоем — кэш при изменении кода
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# dirsearch — клонируем в /opt/dirsearch и устанавливаем его зависимости
RUN git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch && \
    pip install --no-cache-dir -r /opt/dirsearch/requirements.txt

# nuclei — качаем бинарник с GitHub Releases
ARG NUCLEI_VERSION=3.3.5
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent || true

# Код приложения
COPY app ./app
COPY scripts ./scripts

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DIRSEARCH_PATH=/opt/dirsearch/dirsearch.py \
    DIRSEARCH_DIR=/opt/dirsearch \
    NUCLEI_BIN=/usr/local/bin/nuclei

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]