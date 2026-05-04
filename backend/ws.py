"""
ws.py — WebSocket de metricas em tempo real (push para painel admin/cliente).

A conexao e autenticada via cookie de sessao (admin_session ou client_session)
e filtrada por tenant: admin recebe tudo, cliente so seus hostnames.

SEC (Onda 2 SEC-2.2): caps anti-DoS:
  - WS_RECEIVE_TIMEOUT_S — limite de inatividade entre mensagens. Sem isso,
    ws.receive_text() em loop infinito permitia slow-loris-WS (atacante abre
    conexao e nao manda nada, FD pendurado).
  - WS_MAX_PER_IDENTITY — cap de conexoes simultaneas por identidade
    (username). Antes, 1 cookie podia abrir N conexoes; FD exhaustion.

Use:
    from ws import ws_manager, register_websocket
    register_websocket(app)            # registra o endpoint /ws/live
    await ws_manager.broadcast({...})  # envia para conexoes autorizadas
"""

import asyncio
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

import db
from auth import _verify_admin_cookie, _verify_client_cookie

logger = logging.getLogger("infra-vision.api")


# Limite de inatividade — apos esse tempo, backend envia ping. Cliente JS ja
# faz reconnect automatico se conexao morrer, entao 60s e seguro pra ele.
WS_RECEIVE_TIMEOUT_S = 60

# Quantos pings sem reposta antes de encerrar a conexao (~3 minutos com
# WS_RECEIVE_TIMEOUT_S=60). Apos isso, considera peer morto.
WS_MAX_PINGS_NO_REPLY = 3

# Cap de conexoes simultaneas por identidade (username + role). Default
# generoso o suficiente pra cobrir refresh + multi-tab; aperta abuse.
WS_MAX_PER_IDENTITY = {"admin": 5, "client": 3}


class WSManager:
    """Gerencia conexoes WebSocket ativas com filtro por tenant + cap.

    SEC: cada conexão guarda identity + conjunto de hostnames permitidos:
      - identity: "admin:<user>" ou "client:<user>" — usado pra cap por usuario
      - allowed:
          None     -> admin: recebe tudo
          set[str] -> cliente: so hostnames associados
    """
    def __init__(self):
        # lista de tuplas (ws, identity, allowed_hostnames_or_None)
        self._connections: list[tuple] = []

    def _count_for(self, identity: str) -> int:
        return sum(1 for _w, ident, _a in self._connections if ident == identity)

    async def connect(
        self,
        ws,
        identity: str,
        role: str,
        allowed_hostnames=None,
    ) -> bool:
        """Aceita ws + registra. Retorna True se aceito; False se cap atingido.
        Caller deve fechar com code 4429 se False (sem ws.accept() antes —
        nao podemos chamar close em ws nao-aceito; aceito so dentro do True)."""
        cap = WS_MAX_PER_IDENTITY.get(role, 3)
        if self._count_for(identity) >= cap:
            return False
        await ws.accept()
        allowed = None if allowed_hostnames is None else set(allowed_hostnames)
        self._connections.append((ws, identity, allowed))
        return True

    def disconnect(self, ws):
        self._connections = [
            (w, ident, a) for (w, ident, a) in self._connections if w is not ws
        ]

    async def broadcast(self, data: dict):
        """Envia data para conexões autorizadas. data deve conter 'hostname'."""
        hostname = data.get("hostname")
        dead = []
        for ws, _ident, allowed in self._connections:
            # Filtro: admin (allowed=None) recebe tudo; cliente só se hostname está no set
            if allowed is not None and hostname not in allowed:
                continue
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


ws_manager = WSManager()


def register_websocket(app: FastAPI) -> None:
    """Registra o endpoint /ws/live no app."""

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket):
        """WebSocket para metricas em tempo real.

        SEC: autenticacao via cookie de sessao (admin ou client), nunca via
        query param ?token (evita token em server logs / referer / browser history).
          - admin_session cookie valido -> recebe broadcast de todos hostnames
          - client_session cookie valido -> recebe apenas hostnames associados
          - nenhum cookie valido -> 4401 Unauthorized
          - cap de conexoes/identidade excedido -> 4429 Too Many Connections
          - inativo > N timeouts consecutivos -> encerrado server-side
        """
        cookies = websocket.cookies
        identity = None
        role = None
        allowed_hostnames = None

        admin_info = _verify_admin_cookie(cookies.get("admin_session", ""))
        if admin_info:
            identity = f"admin:{admin_info['username']}"
            role = "admin"
            allowed_hostnames = None
        else:
            client_user = _verify_client_cookie(cookies.get("client_session", ""))
            if not client_user:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            user = await db.get_client(client_user)
            if not user or not user.get("active"):
                await websocket.close(code=4403, reason="Inactive client")
                return
            identity = f"client:{client_user}"
            role = "client"
            allowed_hostnames = user.get("hostnames") or []

        # SEC (SEC-2.2): cap de conexoes/identidade
        accepted = await ws_manager.connect(
            websocket, identity, role, allowed_hostnames,
        )
        if not accepted:
            logger.warning(
                "WS rejeitada: %s atingiu cap %d",
                identity, WS_MAX_PER_IDENTITY.get(role, 3),
            )
            await websocket.close(code=4429, reason="Too many connections")
            return

        logger.info(
            "WS connected: %s (cap %d, total %d)",
            identity, WS_MAX_PER_IDENTITY.get(role, 3), ws_manager.count,
        )

        # SEC (SEC-2.2): loop com timeout — slow-loris-WS impossivel agora.
        # Cada timeout envia ping; apos N pings sem reposta, encerra.
        idle_pings = 0
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=WS_RECEIVE_TIMEOUT_S,
                    )
                    # Cliente respondeu — reseta contador
                    idle_pings = 0
                    # Suporta heartbeat ping/pong opcional do cliente
                    if msg and msg.startswith('{"type":"ping"'):
                        try:
                            await websocket.send_json({"type": "pong"})
                        except Exception:
                            break
                except asyncio.TimeoutError:
                    idle_pings += 1
                    if idle_pings > WS_MAX_PINGS_NO_REPLY:
                        logger.info("WS encerrada por idle: %s", identity)
                        break
                    try:
                        await websocket.send_json({"type": "ping"})
                    except Exception:
                        break
        except WebSocketDisconnect:
            pass
        finally:
            ws_manager.disconnect(websocket)
