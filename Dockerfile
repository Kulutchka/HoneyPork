FROM python:3.11-slim

# libpcap is needed by scapy for packet capture on Linux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8080 21 22 23 80 443 1433 3306 3389

CMD ["python", "-m", "app.main"]
