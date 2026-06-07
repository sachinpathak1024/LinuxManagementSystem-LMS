"""WebSocket hub for pushing live metrics & events to the dashboard."""
from __future__ import annotations

import asyncio
import json

from fastapi import WebSocket

from .core.security import decode_token


class Hub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        msg = json.dumps(payload, default=str)
        dead = []
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


hub = Hub()


async def ws_endpoint(ws: WebSocket) -> None:
    # Token passed as query param (?token=...) since browsers can't set headers on WS.
    token = ws.query_params.get("token", "")
    if not decode_token(token):
        await ws.close(code=4401)
        return
    await hub.connect(ws)
    try:
        while True:
            # We don't expect client messages; keep the connection alive.
            await ws.receive_text()
    except Exception:  # noqa: BLE001 - normal disconnect
        pass
    finally:
        await hub.disconnect(ws)
