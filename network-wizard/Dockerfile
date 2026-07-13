FROM python:3.11-slim

# system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    cargo \
    pkg-config \
    iputils-ping \
    traceroute \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# upgrade pip and install wheel first
RUN pip install --no-cache-dir --upgrade pip wheel setuptools

# install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy app files
COPY app.py .
COPY static/ static/
COPY scripts/ scripts/

# download socket.io client — only external dependency needed at runtime
RUN mkdir -p static/vendor && \
    curl -sL "https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.0/socket.io.min.js" \
         -o static/vendor/socket.io.min.js && \
    wc -c static/vendor/socket.io.min.js

# create data directories
RUN mkdir -p data uploads backups logs scripts

EXPOSE 5000

CMD ["python", "app.py"]
