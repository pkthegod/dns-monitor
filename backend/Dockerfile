FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl coreutils less && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser
USER appuser

EXPOSE 8000

# Healthcheck embutido — funciona mesmo fora do docker-compose
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# 1 worker — scheduler de alertas não pode rodar em múltiplos processos.
# --proxy-headers + FORWARDED_ALLOW_IPS: respeita X-Forwarded-Proto/For do
# nginx/Cloudflare. Sem isso, request.url.scheme vira http e cookies secure
# nao funcionam mesmo com TLS na borda. Default 127.0.0.1 = nginx local.
# Em prod com nginx em outro container, ajuste FORWARDED_ALLOW_IPS pro IP do
# gateway docker (ex: 172.20.0.1) ou range CIDR.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]