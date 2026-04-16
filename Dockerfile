# syntax=docker/dockerfile:1.6
# Image BugBounty-AI — Python 3.11 + outils recon Go.
# Conçu pour Railway / Render / Fly.io / VPS Docker.

FROM golang:1.22-bookworm AS gobuilder

ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/gf@latest


FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/byAz1nee/BugBounty-AI"
LABEL org.opencontainers.image.description="Copilote bug bounty autonome (Claude)"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget ca-certificates jq dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobuilder /go/bin/subfinder /usr/local/bin/
COPY --from=gobuilder /go/bin/httpx /usr/local/bin/
COPY --from=gobuilder /go/bin/katana /usr/local/bin/
COPY --from=gobuilder /go/bin/gau /usr/local/bin/
COPY --from=gobuilder /go/bin/waybackurls /usr/local/bin/
COPY --from=gobuilder /go/bin/assetfinder /usr/local/bin/
COPY --from=gobuilder /go/bin/gf /usr/local/bin/

WORKDIR /app

COPY requirements.txt /app/
RUN pip install -r requirements.txt && \
    pip install "python-telegram-bot[job-queue]>=21.0"

RUN git clone --depth=1 https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider && \
    pip install -r /opt/ParamSpider/requirements.txt && \
    printf '#!/bin/bash\nexec python3 /opt/ParamSpider/paramspider.py "$@"\n' > /usr/local/bin/paramspider && \
    chmod +x /usr/local/bin/paramspider

COPY . /app

RUN mkdir -p /app/recon /app/rapport /app/findings/_candidates /app/state /app/js

EXPOSE 8080

# Railway/Render exposent $PORT ; fallback 8080 en local.
CMD ["sh", "-c", "python3 webapp.py --host 0.0.0.0 --port ${PORT:-8080}"]
