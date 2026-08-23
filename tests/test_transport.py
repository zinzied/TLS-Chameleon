"""Phase 1 transport-layer tests (synchronous).

Covers: backend selection/fallback, missing-dependency degradation,
honest capability reporting, proxy translation fixes, and the
backend-isolation architecture rule.
"""

import re
from pathlib import Path

import pytest

import tls_chameleon
from tls_chameleon import TLSChameleon
from tls_chameleon.transport import (
    BackendUnavailableError,
    Capabilities,
    HttpxTransport,
    SessionConfig,
    available_backends,
    select_transport,
)
from tls_chameleon.transport import factory as transport_factory
from tls_chameleon.transport.curl_backend import CurlTransport


@pytest.fixture(autouse=True)
def _reset_warn_cache():
    """Keep the factory warn-once cache isolated between tests."""
    transport_factory._warned.clear()
    yield
    transport_factory._warned.clear()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def test_auto_selection_prefers_curl_when_available():
    from tls_chameleon.transport.primp_backend import PrimpTransport

    backend = select_transport(None)
    if CurlTransport.is_available():
        expected = "curl"
    elif PrimpTransport.is_available():
        expected = "native"  # [native] extra outranks httpx by design
    else:
        expected = "httpx"
    assert backend.name == expected


def test_explicit_backend_respected():
    # httpx is a core dependency, so it must always be selectable.
    assert select_transport("httpx").name == "httpx"


def test_unavailable_preferred_backend_falls_back(caplog):
    original = CurlTransport.is_available.__func__
    try:
        CurlTransport.is_available = classmethod(lambda cls: False)
        with caplog.at_level("WARNING", logger="tls_chameleon.transport.factory"):
            backend = select_transport("curl")
        assert backend.name == "httpx"
        assert any("not available" in r.message for r in caplog.records)
    finally:
        CurlTransport.is_available = classmethod(original)


def test_no_backends_raises_informative_error():
    original_curl = CurlTransport.is_available.__func__
    original_httpx = HttpxTransport.is_available.__func__
    try:
        CurlTransport.is_available = classmethod(lambda cls: False)
        HttpxTransport.is_available = classmethod(lambda cls: False)
        try:
            from tls_chameleon.transport.primp_backend import PrimpTransport

            original_native = PrimpTransport.is_available.__func__
            PrimpTransport.is_available = classmethod(lambda cls: False)
        except ImportError:
            original_native = None
        try:
            with pytest.raises(BackendUnavailableError, match="No networking backend"):
                select_transport(None)
            with pytest.raises(BackendUnavailableError):
                select_transport("httpx")
        finally:
            if original_native is not None:
                PrimpTransport.is_available = classmethod(original_native)
    finally:
        CurlTransport.is_available = classmethod(original_curl)
        HttpxTransport.is_available = classmethod(original_httpx)


def test_unknown_engine_name_warns_and_uses_auto(caplog):
    with caplog.at_level("WARNING", logger="tls_chameleon.transport.factory"):
        backend = select_transport("definitely-not-a-backend")
    assert backend.name in available_backends()
    assert any("Unknown engine" in r.message for r in caplog.records)


def test_client_degrades_without_curl(monkeypatch):
    """The library must keep working when curl_cffi is not installed.

    With the [native] extra present, degradation lands on the native
    backend; otherwise on httpx. Either way: never curl, always usable.
    """
    monkeypatch.setattr(CurlTransport, "is_available", classmethod(lambda cls: False))
    client = TLSChameleon()
    try:
        assert client.engine != "curl"
        assert client.engine in ("native", "httpx")
        assert client.capabilities.backend_name == client.engine
        assert client.session is not None
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Honest capability reporting
# ---------------------------------------------------------------------------

def test_capabilities_match_selected_backend():
    client = TLSChameleon()
    try:
        caps = client.capabilities
        assert isinstance(caps, Capabilities)
        assert caps.backend_name == client.engine
        if client.engine == "httpx":
            # httpx cannot spoof JA3 -- this must be reported honestly.
            assert caps.tls_fingerprint_spoofing is False
            assert caps.http3 is False  # http3 kwarg absent from httpx 0.28+
        else:
            assert caps.tls_fingerprint_spoofing is True
    finally:
        client.close()


def test_fingerprint_info_includes_capabilities():
    client = TLSChameleon()
    try:
        info = client.get_fingerprint_info()
        assert info["capabilities"]["backend"] == info["engine"]
        assert "capabilities" in client.get_fingerprint_info()
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Proxy handling fixes (previously broken on httpx >= 0.28)
# ---------------------------------------------------------------------------

def test_httpx_accepts_constructor_proxies():
    """Regression: proxies used to be assigned to an attribute httpx ignores."""
    transport = HttpxTransport()
    session = transport.create_session(
        SessionConfig(proxies={"http": "http://127.0.0.1:9", "https": "http://127.0.0.1:9"})
    )
    try:
        assert session is not None
    finally:
        session.close()


def test_httpx_adapt_request_translates_proxies_kwarg():
    transport = HttpxTransport()
    session = transport.create_session(SessionConfig())
    try:
        new_session, kwargs = transport.adapt_request(
            session,
            {"proxies": {"http": "http://127.0.0.1:9", "https": "http://127.0.0.1:9"}},
        )
        assert "proxies" not in kwargs
        assert getattr(new_session, "_chameleon_config").proxies is not None
        if new_session is not session:
            new_session.close()
    finally:
        session.close()


def test_httpx_adapt_request_keeps_session_when_proxies_unchanged():
    transport = HttpxTransport()
    proxies = {"http": "http://10.0.0.1:8080", "https": "http://10.0.0.1:8080"}
    session = transport.create_session(SessionConfig(proxies=proxies))
    try:
        new_session, kwargs = transport.adapt_request(session, {"proxies": dict(proxies)})
        assert new_session is session
        assert "proxies" not in kwargs
    finally:
        session.close()


@pytest.mark.skipif(not CurlTransport.is_available(), reason="curl_cffi not installed")
def test_curl_adapt_request_passes_proxies_through():
    transport = select_transport("curl")
    session = transport.create_session(SessionConfig())
    try:
        same_session, kwargs = transport.adapt_request(
            session, {"proxies": {"http": "http://127.0.0.1:9"}}
        )
        assert same_session is session
        assert kwargs["proxies"] == {"http": "http://127.0.0.1:9"}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Session state compatibility
# ---------------------------------------------------------------------------

def test_export_import_roundtrip_preserves_engine():
    client = TLSChameleon(engine="httpx")
    try:
        state = client.export_session()
        assert state["engine"] == "httpx"
        client.import_session(state)
        assert client.engine == "httpx"
        assert client._transport.name == "httpx"
    finally:
        client.close()


def test_engine_attribute_stays_synced_after_rotation_reinit():
    client = TLSChameleon(engine="httpx")
    try:
        client._init_session()
        assert client.engine == "httpx"
        assert client.session is not None
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Architecture rule: backend isolation
# ---------------------------------------------------------------------------

def test_backends_import_networking_libs_only_inside_transport():
    """Only transport backends (+ the benchmark comparison harness) may
    import curl_cffi/httpx directly.

    The request path (client/, fingerprint/, diagnostics/, security/) must
    never touch backend libraries. `benchmark.py` is a sanctioned exception:
    its purpose is measuring those libraries directly, like tests do.
    """
    package_dir = Path(tls_chameleon.__file__).parent
    allowed = {
        package_dir / "transport" / "curl_backend.py",
        package_dir / "transport" / "httpx_backend.py",
        package_dir / "transport" / "primp_backend.py",
        # Explicit, documented exception -- keep this list short.
        package_dir / "benchmark.py",
    }
    pattern = re.compile(
        r"^\s*(?:from|import)\s+(curl_cffi|httpx|primp)\b", re.MULTILINE
    )
    violations = []
    for py_file in package_dir.rglob("*.py"):
        if py_file in allowed or "__pycache__" in py_file.parts:
            continue
        source = py_file.read_text(encoding="utf-8")
        match = pattern.search(source)
        if match:
            violations.append(f"{py_file.name}: imports '{match.group(1)}'")
    assert violations == [], f"Backend isolation violated: {violations}"


def test_request_path_modules_stay_backend_free():
    """The core request path may NEVER import networking libs, even though
    benchmark.py is allow-listed above."""
    package_dir = Path(tls_chameleon.__file__).parent
    strict = [
        package_dir / "client.py",
        package_dir / "async_client.py",
        package_dir / "fingerprint",
        package_dir / "diagnostics",
        package_dir / "security",
        package_dir / "profiles.py",
        package_dir / "magnet.py",
    ]
    pattern = re.compile(
        r"^\s*(?:from|import)\s+(curl_cffi|httpx|primp)\b", re.MULTILINE
    )
    violations = []
    for item in strict:
        files = [item] if item.is_file() else sorted(item.glob("*.py"))
        for py_file in files:
            source = py_file.read_text(encoding="utf-8")
            if pattern.search(source):
                violations.append(py_file.name)
    assert violations == [], f"Request-path isolation violated: {violations}"


def test_transport_package_exports_are_backend_free_names():
    """Public names must not leak backend classes into the top-level API."""
    public = set(dir(tls_chameleon))
    assert "ChameleonResponse" in public
    assert "TLSSession" in public
    assert "AsyncSession" in public
    assert not any(name.lower().startswith("curl") for name in public)
