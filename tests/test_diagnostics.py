"""Phase 3 diagnostics tests: trace, inspect, doctor, client integration."""

import json
from datetime import timedelta

import pytest

from tls_chameleon import TLSChameleon
from tls_chameleon.diagnostics import (
    NetworkTrace,
    collect_trace,
    inspect_url,
    doctor,
)
from tls_chameleon.diagnostics.trace import normalize_http_version


# ---------------------------------------------------------------------------
# Fake backend responses (duck-typed like curl_cffi / httpx)
# ---------------------------------------------------------------------------

class _CurlLikeResponse:
    status_code = 200
    http_version = 3  # libcurl enum -> h2
    primary_ip = "93.184.216.34"
    local_ip = "192.168.0.10"
    redirect_count = 0
    elapsed = None  # filled per-instance below

    def __init__(self, headers=None):
        self.headers = headers or {"content-type": "text/html", "set-cookie": "sid=1"}
        self.elapsed = timedelta(seconds=0.25)


class _HttpxLikeResponse:
    status_code = 200

    def __init__(self):
        self.headers = {"server": "unit"}
        self.extensions = {
            "http_version": b"HTTP/1.1",
            "network_stream": _FakeStream(),
        }

    @property
    def text(self):
        return "ok"


class _FakeStream:
    def get_extra_info(self, key):
        return {"server_addr": ("104.20.23.154", 443)}.get(key)


class _FakeSession:
    """Duck-typed session usable by clients, inspect and doctor."""

    def __init__(self, response=None, fail=False):
        self.response = response or _HttpxLikeResponse()
        self.fail = fail
        self.closed = False

    def request(self, method, url, **kwargs):
        if self.fail:
            raise ConnectionError("unreachable")
        return self.response

    def close(self):
        self.closed = True


class _FakeAsyncSession(_FakeSession):
    """Async variant: request()/aclose() are coroutines."""

    async def request(self, method, url, **kwargs):
        if self.fail:
            raise ConnectionError("unreachable")
        return self.response

    async def aclose(self):
        self.closed = True


def _make_client(engine="httpx", session=None):
    client = TLSChameleon(engine=engine, timeout=5)
    client.session = session or _FakeSession()
    return client


# ---------------------------------------------------------------------------
# Protocol normalization
# ---------------------------------------------------------------------------

class TestProtocolNormalization:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (3, "h2"),
            (2, "http/1.1"),
            (30, "h3"),
            (b"HTTP/1.1", "http/1.1"),
            ("HTTP/2", "h2"),
            ("h3", "h3"),
            ("weird", None),
            (None, None),
        ],
    )
    def test_mapping(self, value, expected):
        assert normalize_http_version(value) == expected


# ---------------------------------------------------------------------------
# collect_trace
# ---------------------------------------------------------------------------

class TestCollectTrace:
    def test_curl_style_response(self):
        trace = collect_trace(
            "GET", "https://example.com/", _CurlLikeResponse(),
            backend="curl", profile="chrome_120",
            request_headers={"Authorization": "Bearer x", "accept": "*/*"},
            total_ms=250.4,
        )
        assert trace.protocol == "h2"
        assert trace.remote_ip == "93.184.216.34"
        assert trace.timing_ms["server_reported_total"] == pytest.approx(250.0)
        assert trace.timing_ms["total"] == pytest.approx(250.4)
        # Redaction applied inside the trace
        assert trace.request_headers["Authorization"] == "[REDACTED]"
        assert trace.response_headers["set-cookie"] == "[REDACTED]"
        assert trace.tls_version is None
        assert any("tls_version not observable" in n for n in trace.notes)

    def test_httpx_style_response(self):
        trace = collect_trace("GET", "https://x/", _HttpxLikeResponse(), backend="httpx")
        assert trace.protocol == "http/1.1"
        assert trace.remote_ip == "104.20.23.154"

    def test_error_trace(self):
        trace = collect_trace(
            "GET", "https://x/", backend="httpx", error=ConnectionError("boom")
        )
        assert trace.status_code is None
        assert any("ConnectionError" in n for n in trace.notes)

    def test_to_dict_is_stable_json(self):
        payload = collect_trace(
            "get", "https://x/", _CurlLikeResponse(), backend="curl"
        ).to_dict()
        encoded = json.dumps(payload)
        assert '"backend": "curl"' in encoded
        assert "schema" not in payload  # plain trace has no schema wrapper


# ---------------------------------------------------------------------------
# inspect_url
# ---------------------------------------------------------------------------

class TestInspectUrl:
    def test_inspect_with_injected_client(self):
        client = _make_client()
        try:
            result = inspect_url("https://unit.test/", client)
            assert result.error is None
            assert result.trace.backend == "httpx"
            assert result.trace.status_code == 200
            data = result.to_dict()
            assert data["trace"]["connection"]["protocol"] == "http/1.1"
            assert data["fingerprint"]["profile_name"] == client.profile_name
        finally:
            client.close()

    def test_inspect_text_output(self):
        result = inspect_url("https://unit.test/", _make_client())
        text = result.to_text()
        for token in ("URL", "Status", "Protocol", "Backend"):
            assert token in text

    def test_inspect_failure_reported_not_raised(self):
        client = _make_client(session=_FakeSession(fail=True))
        try:
            result = inspect_url("https://dead.test/", client)
            assert result.error is not None
            assert "ConnectionError" in result.error
        finally:
            client.close()

    def test_inspect_redacts_url_credentials(self):
        result = inspect_url("https://user:pw@unit.test/x", _make_client())
        assert "user:pw" not in result.to_dict()["url"]

    def test_inspect_echo_mode_merges_fingerprint(self, monkeypatch):
        from tls_chameleon.fingerprint import CaptureResult
        from tls_chameleon.fingerprint.model import Fingerprint, Metadata

        fp = Fingerprint(name="echo", metadata=Metadata(source="captured"))
        captured_with = {}

        def fake_capture(**kwargs):
            captured_with.update(kwargs)
            return CaptureResult(
                endpoint=kwargs["url"], fingerprint=fp, raw={}, captured_at="now"
            )

        import tls_chameleon.diagnostics.inspector as inspector

        monkeypatch.setattr(
            inspector,
            "_capture_fingerprint",
            lambda c, url, t: fake_capture(
                session=c.session, url=url, timeout=t
            ).fingerprint.to_dict(),
        )
        client = _make_client()
        try:
            result = inspect_url("https://unit.test/", client,
                                 echo_endpoint="https://echo.test/")
            assert captured_with["session"] is client.session
            assert result.trace.fingerprint is not None
            assert result.trace.fingerprint["metadata"]["source"] == "captured"
        finally:
            client.close()


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

class TestDoctor:
    def test_healthy_client_has_no_failures(self):
        client = _make_client()
        try:
            report = doctor("https://unit.test/", client)
            by_name = {c.name: c for c in report.checks}
            # httpx + impersonating profile => expected capability warning,
            # so 'warn' is the *healthy* verdict on this backend.
            assert report.verdict == "warn"
            assert by_name["Backend"].status == "warn"
            assert by_name["Profile"].status == "ok"
            assert by_name["Security"].status == "ok"
            assert not any(c.status == "fail" for c in report.checks)
        finally:
            client.close()

    def test_capability_warning_for_httpx(self):
        client = _make_client()  # default chrome profile requests impersonation
        try:
            report = doctor("https://unit.test/", client)
            backend_check = next(c for c in report.checks if c.name == "Backend")
            assert backend_check.status == "warn"
            assert "[curl]" in backend_check.recommendation
        finally:
            client.close()

    def test_unreachable_target_fails(self):
        client = _make_client(session=_FakeSession(fail=True))
        try:
            report = doctor("https://dead.test/", client)
            conn = next(c for c in report.checks if c.name == "Connection")
            assert conn.status == "fail"
            assert report.verdict == "fail"
        finally:
            client.close()

    def test_disabled_verification_warns(self):
        client = TLSChameleon(engine="httpx", verify=False, timeout=5)
        client.session = _FakeSession()
        try:
            report = doctor("https://unit.test/", client)
            sec = next(c for c in report.checks if c.name == "Security")
            assert sec.status == "warn"
            assert sec.recommendation
        finally:
            client.close()

    def test_echo_mode_settings_comparison(self, monkeypatch):
        from tls_chameleon.fingerprint import CaptureResult
        from tls_chameleon.fingerprint.model import (
            Fingerprint, HTTP2Fingerprint, Metadata, TLSFingerprint,
        )

        observed = Fingerprint(
            name="echo",
            tls=TLSFingerprint(),
            http2=HTTP2Fingerprint(settings={"HEADER_TABLE_SIZE": 4096}),
            metadata=Metadata(source="captured"),
        )

        def fake_capture(**kwargs):
            return CaptureResult(endpoint=kwargs["url"],
                                 fingerprint=observed, raw={},
                                 captured_at="now")

        # doctor.py imports `capture` lazily inside the check function,
        # so patching the source module attribute takes effect per call.
        monkeypatch.setattr("tls_chameleon.fingerprint.capture", fake_capture)

        client = _make_client()
        try:
            report = doctor("https://unit.test/", client,
                            echo_endpoint="https://echo.test/")
            h2 = next(c for c in report.checks if c.name == "HTTP/2 SETTINGS")
            assert h2.status == "warn"
            assert "differ" in h2.detail
        finally:
            client.close()

    def test_report_serializable_and_text(self):
        report = doctor("https://unit.test/", _make_client())
        data = report.to_dict()
        assert data["verdict"] in {"ok", "warn", "fail"}
        assert all(set(c.keys()) == {"name", "status", "detail", "recommendation"}
                   for c in data["checks"])
        text = report.to_text()
        assert "TLS-Chameleon Doctor" in text
        assert f"Verdict: {report.verdict.upper()}" in text


# ---------------------------------------------------------------------------
# Client integration (trace=True through the real client path)
# ---------------------------------------------------------------------------

class TestClientTraceIntegration:
    def test_sync_request_with_trace(self):
        client = TLSChameleon(engine="httpx", timeout=5)
        client.session = _FakeSession(_HttpxLikeResponse())
        try:
            resp = client.get("http://unit.test/", headers={"X-A": "1"}, trace=True)
            assert resp.trace is not None
            assert resp.trace.backend == "httpx"
            assert resp.trace.protocol == "http/1.1"
            assert resp.trace.timing_ms["total"] > 0
        finally:
            client.close()

    def test_sync_request_without_trace_is_none(self):
        client = TLSChameleon(engine="httpx", timeout=5)
        client.session = _FakeSession()
        try:
            resp = client.get("http://unit.test/")
            assert resp.trace is None
        finally:
            client.close()

    def test_trace_kwarg_never_reaches_backend(self):
        seen_kwargs = {}

        class _Spy(_FakeSession):
            def request(self, method, url, **kwargs):
                seen_kwargs.update(kwargs)
                return super().request(method, url, **kwargs)

        client = TLSChameleon(engine="httpx", timeout=5)
        client.session = _Spy()
        try:
            client.get("http://unit.test/", trace=True)
            assert "trace" not in seen_kwargs
        finally:
            client.close()


class TestAsyncTraceIntegration:
    @pytest.mark.asyncio
    async def test_async_request_with_trace(self):
        from tls_chameleon import AsyncSession

        client = AsyncSession(engine="httpx", timeout=5)
        client._init_session()
        client.session = _FakeAsyncSession(_HttpxLikeResponse())
        try:
            resp = await client.get("http://unit.test/", trace=True)
            assert resp.trace is not None
            assert resp.trace.backend == "httpx"
            assert resp.trace.profile == client.profile_name
        finally:
            aclose = getattr(client.session, "aclose", None)
            if aclose:
                await aclose()


# ---------------------------------------------------------------------------
# NetworkTrace standalone
# ---------------------------------------------------------------------------

def test_network_trace_defaults_are_none():
    trace = NetworkTrace()
    assert trace.tls_version is None
    assert trace.alpn is None
    assert trace.to_dict()["connection"]["tls_version"] is None
