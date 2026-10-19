"""Verify Grand Slam uses separate connections while other hosts retain pooling."""

# ruff: noqa: SLF001

import asyncio
import base64
import socket
import warnings
from unittest.mock import patch

import pytest
from aiohttp import TCPConnector, web
from aiohttp.abc import AbstractResolver, ResolveResult
from typing_extensions import override

from findmy.util.http import HttpSession


class _LoopbackResolver(AbstractResolver):
    @override
    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": family,
                "proto": 0,
                "flags": 0,
            }
        ]

    @override
    async def close(self) -> None:
        pass


def test_only_grand_slam_uses_a_new_connection_for_each_request() -> None:
    """Keep GSA connections separate and Basic Auth bytes unchanged without warnings."""

    async def run() -> None:
        connections: list[asyncio.BaseTransport | None] = []

        async def handler(request: web.Request) -> web.Response:
            expected_auth = (
                "Basic " + base64.b64encode("fixture:pássword".encode("latin1")).decode()
            )
            assert request.headers.get("Authorization") == expected_auth
            reused = any(request.transport is item for item in connections)
            connections.append(request.transport)
            return web.Response(status=429 if reused else 200)

        app = web.Application()
        app.router.add_post("/login", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]

        def connector(*, force_close: bool) -> TCPConnector:
            return TCPConnector(resolver=_LoopbackResolver(), force_close=force_close)

        session = HttpSession()
        try:
            with patch("findmy.util.http.TCPConnector", connector), warnings.catch_warnings():
                warnings.simplefilter("error", DeprecationWarning)
                for host, expected in [
                    ("gsa.apple.com", [200, 200]),
                    ("setup.icloud.com", [200, 429]),
                ]:
                    statuses = []
                    for _ in range(2):
                        response = await session.post(
                            f"http://{host}:{port}/login",
                            data=b"fixture",
                            auth=("fixture", "pássword"),
                        )
                        statuses.append(response.status_code)
                    assert statuses == expected
            clients = (session._session, session._unpooled)
            await session.close()
            assert all(client is not None and client.closed for client in clients)
            with pytest.raises(RuntimeError, match="closed"):
                await session._get_session("https://gsa.apple.com")
        finally:
            await session.close()
            await runner.cleanup()

    asyncio.run(run())
