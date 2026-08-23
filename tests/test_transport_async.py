"""Async transport tests.

Runs only when pytest-asyncio is installed; skipped gracefully in CI
environments without the plugin.
"""

import pytest

pytest.importorskip("pytest_asyncio")

from tls_chameleon import AsyncSession
from tls_chameleon.transport import SessionConfig, select_transport


@pytest.mark.asyncio
async def test_async_session_constructs_via_transport():
    async with AsyncSession(engine="httpx") as client:
        assert client.engine == "httpx"
        assert client.session is not None
        assert hasattr(client.session, "aclose")


@pytest.mark.asyncio
async def test_async_adapt_request_strips_proxies_for_httpx():
    transport = select_transport("httpx")
    session = transport.create_async_session(SessionConfig())
    try:
        new_session, kwargs = await transport.adapt_request_async(
            session,
            {"proxies": {"http": "http://127.0.0.1:9", "https": "http://127.0.0.1:9"}},
        )
        assert "proxies" not in kwargs
    finally:
        await session.aclose()
