"""v3.1 architecture tests: Chameleon API, owned response, ProxyConfig,
SessionState, expanded capabilities, seed alias, compare-backends alias."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import tls_chameleon
from tls_chameleon import (
    AsyncChameleon,
    Chameleon,
    ProxyConfig,
    TLSChameleon,
)
from tls_chameleon.session_state import SessionState


# ---------------------------------------------------------------------------
# Local HTTP server (no external network)
# ---------------------------------------------------------------------------

class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html>v31-ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "k=v31")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def local_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    t.join()


# ---------------------------------------------------------------------------
# M1: Chameleon / AsyncChameleon high-level API
# ---------------------------------------------------------------------------

class TestChameleonAPI:
    def test_chameleon_is_tlssession_subclass(self):
        assert issubclass(Chameleon, TLSChameleon)
        assert issubclass(AsyncChameleon, tls_chameleon.AsyncSession)

    def test_spec_example_constructs_and_requests(self, local_url):
        client = Chameleon(profile="chrome_130_win11", engine="httpx",
                           adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            r = client.get(local_url)
            assert r.status_code == 200
            assert client.profile_name == "chrome_130_win11"
        finally:
            client.close()

    def test_backend_alias_sets_engine(self):
        c = Chameleon(backend="httpx", timeout=5)
        try:
            assert c.engine == "httpx"
        finally:
            c.close()

    def test_exported_from_package_root(self):
        assert hasattr(tls_chameleon, "Chameleon")
        assert hasattr(tls_chameleon, "AsyncChameleon")

    @pytest.mark.asyncio
    async def test_async_chameleon(self, local_url):
        from tls_chameleon import AsyncSession

        client = AsyncChameleon(backend="httpx", timeout=10)
        assert isinstance(client, AsyncSession)
        client._init_session()
        client.session = _FakeAsyncSession()
        try:
            r = await client.get(local_url)
            assert r.status_code == 200
        finally:
            aclose = getattr(client.session, "aclose", None)
            if aclose:
                await aclose()


# ---------------------------------------------------------------------------
# M2: owned response surface
# ---------------------------------------------------------------------------

class _HttpxLike:
    status_code = 200

    def __init__(self):
        self.headers = {"server": "unit"}
        self.cookies = {"k": "v31"}
        self.extensions = {"http_version": b"HTTP/1.1"}

    @property
    def text(self):
        return "<html>v31-ok</html>"

    content = b"<html>v31-ok</html>"
    url = "http://127.0.0.1/"
    encoding = None
    history = []

    def json(self, **kw):
        return {"ok": True}


class _FakeAsyncSession:
    def __init__(self, response=None):
        self.response = response or _HttpxLike()

    async def request(self, method, url, **kw):
        return self.response

    async def aclose(self):
        pass


def _fake_session(response=None):
    class _S:
        def __init__(self):
            self.response = response or _HttpxLike()

        def request(self, method, url, **kw):
            return self.response

        def close(self):
            pass

    return _S()


class TestOwnedResponse:
    def test_explicit_surface_works(self, local_url):
        client = Chameleon(engine="httpx", adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            r = client.get(local_url)
            assert r.status_code == 200
            assert "v31-ok" in r.text
            assert r.headers["server"] == "unit"
            assert r.cookies["k"] == "v31"
            assert r.ok is True
            assert r.json() == {"ok": True}
            assert isinstance(r.headers, dict)
        finally:
            client.close()

    def test_backend_attributes_no_longer_leak(self, local_url):
        client = Chameleon(engine="httpx", adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            r = client.get(local_url)
            # httpx-internal names must NOT proxy through anymore.
            with pytest.raises(AttributeError, match="Supported"):
                _ = r.extensions
            with pytest.raises(AttributeError):
                _ = r.network_stream
        finally:
            client.close()

    def test_error_message_lists_supported_fields(self, local_url):
        client = Chameleon(engine="httpx", adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            r = client.get(local_url)
            with pytest.raises(AttributeError) as excinfo:
                _ = r.definitely_not_a_field
            msg = str(excinfo.value)
            for field in ("status_code", "text", "headers", "magnet", "trace"):
                assert field in msg
        finally:
            client.close()


# ---------------------------------------------------------------------------
# M3: expanded capability vocabulary
# ---------------------------------------------------------------------------

class TestCapabilitiesVocabulary:
    def test_new_fields_present_on_all_backends(self):
        from tls_chameleon.transport import available_backends

        for name in available_backends():
            caps = select_transport_caps(name).to_dict()
            for key in ("http1", "tls_customization", "websocket",
                        "fingerprint_capture"):
                assert key in caps, f"{name} missing capability {key}"

    def test_truthful_values(self):
        from tls_chameleon.transport import available_backends

        for name in available_backends():  # only what is truly installed
            cap = select_transport_caps(name)
            if name == "curl":
                assert cap.websocket is True
            else:
                assert cap.websocket is False
            assert cap.fingerprint_capture is False
            assert cap.http1 is True


def select_transport_caps(name):
    from tls_chameleon.transport import select_transport

    return select_transport(name).capabilities


# ---------------------------------------------------------------------------
# M4: ProxyConfig
# ---------------------------------------------------------------------------

class TestProxyConfig:
    def test_coerce_string(self):
        cfg = ProxyConfig.coerce("http://proxy:8080")
        assert cfg.to_requests_dict() == {"http": "http://proxy:8080",
                                          "https": "http://proxy:8080"}

    def test_coerce_dict_roundtrip(self):
        d = {"http": "http://a:1", "https": "https://b:2"}
        assert ProxyConfig.coerce(d).to_requests_dict() == d

    def test_coerce_none_passthrough(self):
        assert ProxyConfig.coerce(None) is None
        cfg = ProxyConfig(http="http://a")
        assert ProxyConfig.coerce(cfg) is cfg

    def test_unknown_keys_preserved(self):
        d = {"http": "http://a", "all": "http://b"}
        out = ProxyConfig.coerce(d).to_requests_dict()
        assert out == d

    def test_client_accepts_proxy_config(self, local_url):
        pcfg = ProxyConfig(http=None, https=None)  # empty -> no proxying
        client = Chameleon(engine="httpx", adaptive=False,
                           timeout=10, proxies=pcfg)
        client.session = _fake_session()
        try:
            assert client.proxies == {}
        finally:
            client.close()

    def test_invalid_type_rejected(self):
        with pytest.raises(TypeError):
            ProxyConfig.coerce(42)


# ---------------------------------------------------------------------------
# M5: SessionState
# ---------------------------------------------------------------------------

class TestSessionState:
    def test_export_uses_session_state_schema(self, local_url):
        client = Chameleon(engine="httpx", adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            state = client.export_session()
            expected_keys = set(SessionState().to_dict().keys())
            assert expected_keys <= set(state.keys())
        finally:
            client.close()

    def test_from_dict_is_lenient(self):
        st = SessionState.from_dict({"profile_name": "x",
                                     "unknown_future_key": 1})
        assert st.profile_name == "x"

    def test_json_safe(self, local_url):
        client = Chameleon(engine="httpx", adaptive=False, timeout=10)
        client.session = _fake_session()
        try:
            encoded = json.dumps(client.export_session())
            assert "curl_cffi" not in encoded
            assert "primp" not in encoded
        finally:
            client.close()


# ---------------------------------------------------------------------------
# M8: seed alias
# ---------------------------------------------------------------------------

class TestSeedAlias:
    def test_seed_alias_deterministic(self):
        a = Chameleon(engine="httpx", randomize=True, seed=123)
        b = Chameleon(engine="httpx", randomize=True, random_seed=123)
        try:
            i1 = a.get_fingerprint_info()
            i2 = b.get_fingerprint_info()
            assert i1["user_agent"] == i2["user_agent"]
            assert i1["random_seed"] == 123
        finally:
            a.close()
            b.close()

    def test_seed_via_module_helper_kwargs(self):
        from tls_chameleon.client import _split_kwargs

        s, r = _split_kwargs({"seed": 7, "params": {"q": 1}})
        assert s["seed"] == 7 and r == {"params": {"q": 1}}
