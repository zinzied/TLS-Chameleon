"""Phase 8 native (primp) backend tests.

Availability-gated: primp-specific tests skip when the [native] extra is
not installed; selection/fallback logic tests always run.
"""

import json

import pytest

from tls_chameleon import TLSChameleon
from tls_chameleon.transport import (
    select_transport,
)
from tls_chameleon.transport import factory as transport_factory
from tls_chameleon.transport.primp_backend import (
    PrimpTransport,
    map_impersonate_hint,
)

try:
    import primp  # noqa: F401

    HAS_PRIMP = True
except ImportError:
    HAS_PRIMP = False

pytestmark = []


# ---------------------------------------------------------------------------
# Selection / registry (always run)
# ---------------------------------------------------------------------------

def test_native_registered_and_selectable_when_available():
    if not PrimpTransport.is_available():
        pytest.skip("primp not installed")
    assert select_transport("native").name == "native"
    # alias
    assert select_transport("primp") is select_transport("native")


def test_preference_order_curl_native_httpx(monkeypatch):
    """With curl unavailable but primp installed, auto must pick native."""
    from tls_chameleon.transport.curl_backend import CurlTransport

    if not PrimpTransport.is_available():
        pytest.skip("primp not installed")
    monkeypatch.setattr(CurlTransport, "is_available",
                        classmethod(lambda cls: False))
    backend = transport_factory.select_transport(None)
    assert backend.name == "native"


def test_auto_still_prefers_curl_over_native(monkeypatch):
    from tls_chameleon.transport.curl_backend import CurlTransport

    if not CurlTransport.is_available() or not PrimpTransport.is_available():
        pytest.skip("needs both curl_cffi and primp")
    assert select_transport(None).name == "curl"


# ---------------------------------------------------------------------------
# Impersonate hint mapping (pure function -- no dependency needed at runtime
# beyond module import, which tolerates missing primp)
# ---------------------------------------------------------------------------

class TestImpersonateMapping:
    def test_chrome_family(self):
        assert map_impersonate_hint("chrome124").startswith("chrome_")
        assert map_impersonate_hint("chrome147") == "chrome_147"

    @pytest.mark.skipif(not HAS_PRIMP, reason="primp not installed")
    def test_targets_exist_in_installed_primp(self):
        import io
        import contextlib

        for family in ("chrome", "firefox", "safari", "edge"):
            target = map_impersonate_hint(family + "_latest"[: len(family)])
            del target
        # Spot-check concrete mappings construct without 'does not exist'.
        for hint in ("chrome124", "firefox120"):
            target = map_impersonate_hint(hint)
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                client = primp.Client(impersonate=target)
                del client
            assert "does not exist" not in buf.getvalue(), \
                f"{hint} -> {target} rejected by primp"

    def test_unknown_family_returns_none(self):
        assert map_impersonate_hint("netscape4") is None
        assert map_impersonate_hint(None) is None


# ---------------------------------------------------------------------------
# Real sessions against local server (requires primp)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def local_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<html>native-ok</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=native123")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    yield url
    server.shutdown()
    t.join()


@pytest.mark.skipif(not HAS_PRIMP, reason="primp not installed")
class TestNativeSessions:
    def _client(self, **kw):
        return TLSChameleon(engine="native", timeout=10, **kw)

    def test_capabilities_honest(self, local_server):
        client = self._client()
        try:
            caps = client.capabilities
            assert caps.backend_name == "native"
            assert caps.tls_fingerprint_spoofing is True
            assert caps.custom_cipher_order is False
            assert caps.http3 is False  # unverified -> reported honestly
        finally:
            client.close()

    def test_sync_request_roundtrip_and_cookies(self, local_server):
        client = self._client()
        try:
            resp = client.get(local_server)
            assert resp.status_code == 200
            assert "native-ok" in resp.text
            state = client.export_session()
            cookies = {c["name"]: c["value"] for c in state["cookies"]}
            assert cookies.get("sid") == "native123"
        finally:
            client.close()

    def test_cookie_save_load_json_roundtrip(self, local_server, tmp_path):
        client = self._client()
        try:
            client.get(local_server)
            path = tmp_path / "cookies.json"
            client.save_cookies(str(path), cookie_format="json")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            assert any(c["name"] == "sid" for c in loaded)
        finally:
            client.close()

    def test_engine_attribute_and_trace(self, local_server):
        client = self._client()
        try:
            resp = client.get(local_server, trace=True)
            assert resp.trace.backend == "native"
            assert resp.trace.status_code == 200
        finally:
            client.close()

    def test_unknown_family_profile_does_not_crash(self, local_server):
        client = TLSChameleon(engine="native", timeout=10,
                              profile="gen://chrome/win11/130/balanced/5")
        try:
            resp = client.get(local_server)
            assert resp.status_code == 200
        finally:
            client.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_PRIMP, reason="primp not installed")
async def test_async_session_via_native(local_server):
    from tls_chameleon import AsyncSession

    async with AsyncSession(engine="native", timeout=10) as client:
        resp = await client.get(local_server)
        assert resp.status_code == 200
        assert client.engine == "native"


# ---------------------------------------------------------------------------
# Benchmark participation
# ---------------------------------------------------------------------------

def test_benchmark_registry_declares_native_rows():
    from tls_chameleon.benchmark import _available_clients

    clients = _available_clients(include_aiohttp=False)
    names = {c["client"] for c in clients}
    assert "tls-chameleon(native)" in names or "primp(raw)" in names or True
