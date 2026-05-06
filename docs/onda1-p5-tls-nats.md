# Onda 1 P5 — TLS no NATS via WebSocket + Cloudflare

**Status:** preparado em 2026-05-06; rolling deploy pendente (exige janela
operacional + rolling restart dos agentes em prod).

## O que o P5 entrega

Antes (estado pos-P4):
- Agentes externos conectam em `nats://<IP_PUBLICO>:4222` em **plaintext**.
- Credenciais NATS, payloads de comandos e acks trafegam abertos.
- Porta 4222 exposta na borda — fingerprint pra atacante.

Depois:
- Agentes conectam em `wss://nats.<dominio>/ws` — TLS terminado no nginx.
- Cloudflare proxy laranja na frente — IP de origem mascarado.
- Porta 4222/8222 fechada pra mundo (so `127.0.0.1:8080` interno).

## Topologia final

```
Agente externo  ──HTTPS─►  Cloudflare (laranja)  ──HTTPS─►  nginx
                                                              │
                                                              │ proxy /ws
                                                              ▼
                                              127.0.0.1:8080 (NATS WS)
                                                              │
                                                              │ WebSocket frame
                                                              ▼
                                              container infra_vision_nats
                                                  (172.20.0.13:8080)
```

## Mudancas no codigo (ja em main)

1. **`backend/nats-server.conf`** ganha bloco `websocket { port: 8080,
   no_tls: true, ... }` — handshake plaintext porque nginx termina TLS.

2. **`backend/docker-compose.yaml`** expoe `127.0.0.1:8080:8080` (so
   loopback do host, nao mundo). Mantem `-p 4222:4222 -p 8222:8222`
   ate todos agentes migrarem.

3. **`agent/agent.toml`** documenta `wss://` como modo recomendado;
   default ainda nats:// pro compat.

## Plano operacional (a fazer no servidor + CF panel)

### 1. Cloudflare

Painel CF do dominio `procyontecnologia.net`:

- DNS → cria record:
  - Type: A
  - Name: `nats`
  - Content: IP do servidor `testelog`
  - Proxy: **laranja** (proxied)
  - TTL: Auto

- SSL/TLS → Origin Server:
  - Cria **Origin Certificate** novo (15 anos)
  - Salva o cert em `/etc/cf-origin/nats.cert.pem` no servidor
  - Salva a key em `/etc/cf-origin/nats.key.pem`

### 2. nginx no servidor (testelog)

Cria `/etc/nginx/sites-available/nats-ws.conf`:

```nginx
# Onda 1 P5 — WebSocket NATS via wss://nats.procyontecnologia.net/ws
server {
    listen 443 ssl http2;
    server_name nats.procyontecnologia.net;

    # Cert da Cloudflare Origin (nao trust em browser, ok atras de CF)
    ssl_certificate     /etc/cf-origin/nats.cert.pem;
    ssl_certificate_key /etc/cf-origin/nats.key.pem;

    # Apenas /ws e proxypassed (resto fica 404)
    location /ws {
        proxy_pass http://127.0.0.1:8080;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket idle longo (NATS heartbeat manda ping a cada ~2min)
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }

    # Bloqueia tudo o resto
    location / {
        return 404;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/nats-ws.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 3. Deploy do NATS atualizado

```bash
cd /opt/dns-monitor && git pull
cd backend && docker compose up -d --force-recreate nats
docker compose logs nats --tail 30 | grep -iE "websocket|listening"
# Esperado: 'Listening for websocket clients on 0.0.0.0:8080'
```

### 4. Validacao do WS antes de migrar agentes

```bash
# No proprio servidor (ou de outro host com nats CLI):
NATS_AGENT_PASS=$(grep ^NATS_PASS /opt/dns-monitor/backend/.env | cut -d= -f2-)

docker run --rm --network host natsio/nats-box:latest \
  nats sub --user dnsmonitor --password "$NATS_AGENT_PASS" \
  -s wss://nats.procyontecnologia.net/ws \
  "dns.commands.>" --timeout 5s
# Esperado: subscribe ativa por 5s sem erro -> WS funciona
```

### 5. Rolling migration dos 11 agentes

**Estrategia canary**: troca 1 agente, valida, depois bulk.

#### Canary (1 agente)

Escolha um agente menos critico (ex: NSR_VELINK ou NS1_LIGOTELECOM).

```bash
ssh root@<host_canary>
sudo nano /etc/dns-agent/agent.toml
# Mudar:
#   url = "nats://<IP>:4222"
# Pra:
#   url = "wss://nats.procyontecnologia.net/ws"
sudo systemctl restart dns-agent
sleep 5
journalctl -u dns_agent --since '30s ago' | grep -iE "nats|conectado"
```

Esperado:
```
NATS conectado: wss://nats.procyontecnologia.net/ws (subscribe: dns.commands.<host>)
```

Valida 30 min em prod. Se OK, segue pros outros 10.

#### Bulk dos 10 restantes

Edita o `agent.toml` em cada host. Como cada agent.toml fica em
`/etc/dns-agent/agent.toml` no host (NAO no /opt/dns-agent/), o
auto-update via UI **nao** atualiza esse arquivo — precisa SSH em
cada um (ou usar `scripts/update_all_agents.sh` se ele cobrir
`agent.toml`).

Recomendo um loop ssh:

```bash
for host in NS1_X NS2_X ...; do
  ssh root@$host "sed -i 's|nats://[^\"]*|wss://nats.procyontecnologia.net/ws|' /etc/dns-agent/agent.toml && systemctl restart dns_agent"
done
```

Confirma cada um conectou via WS via UI: tabela Agentes mostra
`Ultimo heartbeat` recente + comandos de teste chegam < 5s.

### 6. Lockdown final (apos todos migrarem)

```bash
cd /opt/dns-monitor/backend
# Remove exposicao publica de 4222 e 8222:
nano docker-compose.yaml
# Comenta as linhas:
#  - "4222:4222"
#  - "8222:8222"

docker compose up -d --force-recreate nats backend
```

## Rollback se algo der errado

Cada step e reversivel:

- **Step 4 falha**: NATS WS nao subiu. Confere logs. Plain TCP 4222 continua
  funcional pros agentes — sem impacto visivel.
- **Step 5 (canary) falha**: agente reverte agent.toml pra `nats://`,
  volta a conectar plain. Outros 10 continuam funcionando.
- **Step 6 (lockdown) falha**: re-adiciona `-p 4222:4222` no compose,
  agentes que ainda nao migraram voltam a conectar.

## Riscos identificados

1. **CF rate limit** em WebSocket conexoes longas: 100k connections free
   tier. Com 40 agentes esperados, sem problema.

2. **nginx config errada**: se `proxy_read_timeout` nao for grande, NATS
   desconecta agentes a cada N seg. Solucao: 86400s (24h, NATS manda
   ping bem antes).

3. **CF tira o WebSocket em algum plano future**: improvavel; WebSocket
   e suportado em Free desde 2018. Mas se acontecer, alternativa:
   self-hosted TLS direto no NATS (sem CF), abrindo port 4443 com
   cert publico do dominio.

4. **Agente em rede com proxy corporativo bloqueia ws upgrade header**:
   raro mas possivel. Solucao: agent.toml volta pra `nats://` (manter
   compat 4222 ate ter problema reportado).

## Quando o ratchet_lock fecha

`nats_plain_text_4222` no `quality-baseline.json` fecha quando:
1. Todos os 11 agentes em `wss://`
2. `-p 4222:4222 -p 8222:8222` removidos do compose
3. `nmap` no IP publico do servidor nao mostra 4222 aberto

Atualizar `quality-baseline.json` removendo a chave do `ratchet_locks`.
