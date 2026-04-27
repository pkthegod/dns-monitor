"""
ws.py — WebSocket de metricas em tempo real (push para painel admin/cliente).

A conexao e autenticada via cookie de sessao (admin_session ou client_session)
e filtrada por tenant: admin recebe tudo, cliente so seus hostnames.

Use:
    from ws import ws_manager, register_websocket
    register_websocket(app)            # registra o endpoint /ws/live
    await ws_manager.broadcast({...})  # envia para conexoes autorizadas
"""

import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

import db
from auth import _verify_admin_cookie, _verify_client_cookie

logger = logging.getLogger("infra-vision.api")


class WSManager:
    """Gerencia conexoes WebSocket ativas com filtro por tenant.

    SEC: cada conexão guarda o conjunto de hostnames que o ator pode ver.
    - None → admin: recebe tudo
    - set[str] → cliente: recebe só métricas de hostnames associados
    """
    def __init__(self):
        # lista de tuplas (ws, allowed_hostnames_or_None)
        self._connections: list[tuple] = []

    async def connect(self, ws, allowed_hostnames=None):
        await ws.accept()
        allowed = None if allowed_hostnames is None else set(allowed_hostnames)
        self._connections.append((ws, allowed))

    def disconnect(self, ws):
        self._connections = [(w, a) for (w, a) in self._connections if w is not ws]

    async def broadcast(self, data: dict):
        """Envia data para conexões autorizadas. data deve conter 'hostname'."""
        hostname = data.get("hostname")
        dead = []
        for ws, allowed in self._connections:
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
        Antes, qualquer portador do AGENT_TOKEN conectava e recebia metricas de
        todos os hosts, incluindo clientes do portal que extraiam o token de
        /api/v1/session/token. Agora:
          - admin_session cookie valido -> recebe broadcast de todos hostnames
          - client_session cookie valido -> recebe apenas hostnames associados
          - nenhum cookie valido -> 4401 Unauthorized
        """
        cookies = websocket.cookies

        admin_info = _verify_admin_cookie(cookies.get("admin_session", ""))
        if admin_info:
            await ws_manager.connect(websocket, allowed_hostnames=None)
            logger.info("WS connected: admin=%s role=%s (all hosts)", admin_info["username"], admin_info["role"])
        else:
            client_user = _verify_client_cookie(cookies.get("client_session", ""))
            if not client_user:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            user = await db.get_client(client_user)
            if not user or not user.get("active"):
                await websocket.close(code=4403, reason="Inactive client")
                return
            hostnames = user.get("hostnames") or []
            await ws_manager.connect(websocket, allowed_hostnames=hostnames)
            logger.info("WS connected: client=%s (hosts=%s)", client_user, hostnames)

        try:
            while True:
                await websocket.receive_text()  # keepalive
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
