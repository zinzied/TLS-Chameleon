"""Phase 5 CLI tests.

Uses a real local HTTP server (stdlib http.server) so no test touches the
external network. CLI entry is invoked in-process via main(argv).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import tls_chameleon
from tls_chameleon.cli.main import EXIT_ERROR, EXIT_OK, main
from tls_chameleon.cli.common import EXIT_FAILED_CHECK


# ---------------------------------------------------------------------------
# Local HTTP server fixture
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # so httpx reports HTTP/1.1 in extensions

    def log_message(self, *args):  # silence request logging
        pass

    def do_GET(self):
        body = b"<html><body>hello from local server</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "LocalTest/1.0")
        self.send_header("Set-Cookie", "session=topsecret123")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    thread.join()


@pytest.fixture(autouse=True)
def _no_external_network(monkeypatch):
    """Fail loudly if a test accidentally reaches the internet."""
    import socket

    def _blocked(*args, **kwargs):
        raise AssertionError("external network access attempted in CLI tests")

    original = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and not host.startswith("127.0.0.1"):
            return _blocked(address)
        return original(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


# ---------------------------------------------------------------------------
# version / help
# ---------------------------------------------------------------------------

def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "tls-chameleon" in capsys.readouterr().out


def test_python_dash_m_invocation(capsys):
    rc = main(["version"])
    assert rc == EXIT_OK
    assert "tls-chameleon" in capsys.readouterr().out


def test_version_subcommand_json(capsys):
    rc = main(["version", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert payload["schema"] == "tls-chameleon.version/1"
    assert payload["version"] == tls_chameleon.__version__


def test_no_command_shows_help(capsys):
    assert main([]) == EXIT_ERROR


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

class TestGet:
    def test_get_text_mode(self, local_server, capsys):
        rc = main(["get", local_server, "--engine", "httpx",
                   "--max-body", "50"])
        out = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "200 GET" in out
        assert "sensitive header(s) hidden" in out  # Set-Cookie redacted
        assert "topsecret123" not in out

    def test_get_json_mode(self, local_server, capsys):
        rc = main(["get", local_server, "--engine", "httpx", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["schema"] == "tls-chameleon.get/1"
        assert payload["status_code"] == 200
        assert payload["headers"]["set-cookie"] == "[REDACTED]"
        assert "hello from local server" in payload["body"]

    def test_get_with_trace(self, local_server, capsys):
        rc = main(["get", local_server, "--engine", "httpx", "--trace",
                   "--json", "--max-body", "0"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["trace"]["connection"]["protocol"] == "http/1.1"

    def test_get_unreachable_fails_cleanly(self, capsys):
        rc = main(["get", "http://127.0.0.1:1/nope", "--engine", "httpx",
                   "--timeout", "2", "--json"])
        captured = capsys.readouterr()
        assert rc == EXIT_ERROR
        assert captured.out == ""


# ---------------------------------------------------------------------------
# inspect / doctor against the local server
# ---------------------------------------------------------------------------

class TestInspectAndDoctor:
    def test_inspect_json(self, local_server, capsys):
        rc = main(["inspect", local_server, "--engine", "httpx", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["schema"] == "tls-chameleon.inspect/1"
        assert payload["trace"]["response"]["status_code"] == 200
        assert payload["fingerprint"]["profile_name"]

    def test_doctor_json_and_exit_codes(self, local_server, capsys):
        rc = main(["doctor", local_server, "--engine", "httpx", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema"] == "tls-chameleon.doctor/1"
        assert payload["verdict"] in {"ok", "warn"}  # warn: capability note
        names = {c["name"] for c in payload["checks"]}
        assert {"Connection", "Backend", "Profile", "Header consistency"} <= names
        if payload["verdict"] == "fail":
            assert rc == EXIT_FAILED_CHECK
        else:
            assert rc == EXIT_OK

    def test_doctor_fail_on_dead_target(self, capsys):
        rc = main(["doctor", "http://127.0.0.1:1/", "--engine", "httpx",
                   "--timeout", "2", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_FAILED_CHECK
        assert payload["verdict"] == "fail"


# ---------------------------------------------------------------------------
# fingerprint subcommands (pure offline)
# ---------------------------------------------------------------------------

CHROME_PROFILE = {
    "name": "chrome_120_win11",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120"',
    "ja3": ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171"
            "-49172-156-157-47-53,"
            "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"),
}


class TestFingerprintCommand:
    def test_list(self, capsys):
        rc = main(["fingerprint", "list", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["count"] >= 40
        assert "chrome_120_win11" in payload["profiles"]

    def test_list_browser_filter(self, capsys):
        rc = main(["fingerprint", "list", "--browser", "firefox", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert all(n.startswith("firefox") for n in payload["profiles"])

    def test_show_known_profile(self, capsys):
        rc = main(["fingerprint", "show", "chrome_120_win11", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["metadata"]["source"] == "documented"
        assert payload["tls"]["ja3_hash"].startswith("cd08e314")

    def test_show_unknown_profile_errors(self, capsys):
        rc = main(["fingerprint", "show", "not_a_real_profile"])
        assert rc == EXIT_ERROR
        assert "unknown profile" in capsys.readouterr().err
    def test_validate_valid_profile(self, tmp_path, capsys):
        path = tmp_path / "good.json"
        path.write_text(json.dumps(CHROME_PROFILE), encoding="utf-8")
        rc = main(["fingerprint", "validate", str(path)])
        payload = json.loads(capsys.readouterr().out)
        assert payload["valid"] is True
        assert rc == EXIT_OK

    def test_validate_inconsistent_profile_fails(self, tmp_path, capsys):
        bad = dict(CHROME_PROFILE)
        bad["sec_ch_ua"] = '"Firefox";v="121"'  # contradiction!
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        rc = main(["fingerprint", "validate", str(path)])
        payload = json.loads(capsys.readouterr().out)
        assert payload["valid"] is False
        assert any("inconsistency" in e["message"] for e in payload["errors"])
        assert rc == EXIT_FAILED_CHECK

    def test_validate_missing_file(self, tmp_path, capsys):
        rc = main(["fingerprint", "validate", str(tmp_path / "nope.json")])
        assert rc == EXIT_ERROR


# ---------------------------------------------------------------------------
# diff (offline, via capture-style files)
# ---------------------------------------------------------------------------

def _capture_file(tmp_path, name, ja3):
    fingerprint = {
        "schema": "tls-chameleon.fingerprint/1",
        "name": name,
        "tls": {"version": "771", "cipher_ids": [4865], "extension_ids": [0],
                "curve_ids": [29], "point_format_ids": [0]},
        "http2": {"settings": {}},
        "headers": {"order": [], "case": "lower"},
        "metadata": {"source": "captured", "verified": True},
    }
    if ja3:
        fingerprint["tls"]["cipher_ids"] = [4865, 4866]
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({"endpoint": "https://echo.test/",
                                "fingerprint": fingerprint}),
                    encoding="utf-8")
    return path


class TestDiffCommand:
    def test_diff_json_between_captures(self, tmp_path, capsys):
        fa = _capture_file(tmp_path, "cap_a", ja3=False)
        fb = _capture_file(tmp_path, "cap_b", ja3=True)
        rc = main(["diff", str(fa), str(fb), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["a"] == "cap_a" and payload["b"] == "cap_b"
        cipher_verdict = next(v for v in payload["sections"]["TLS"]
                              if v["field"] == "Cipher suites")
        assert cipher_verdict["same"] is False
        assert isinstance(payload["similarity"], float)

    def test_diff_identical_files_all_same(self, tmp_path, capsys):
        fa = _capture_file(tmp_path, "same_a", ja3=True)
        fb = _capture_file(tmp_path, "same_b", ja3=True)
        rc = main(["diff", str(fa), str(fb)])
        text = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "SAME" in text and "DIFFERENT" not in text

    def test_diff_malformed_file_errors(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        good = _capture_file(tmp_path, "ok", ja3=False)
        rc = main(["diff", str(bad), str(good)])
        assert rc == EXIT_ERROR


# ---------------------------------------------------------------------------
# capture + benchmark stubs
# ---------------------------------------------------------------------------

class TestCaptureAndBenchmark:
    def test_capture_mocked_endpoint(self, local_server, monkeypatch, capsys):
        """Capture runs against the local server via a canned mapping."""
        from tls_chameleon.cli import capture as cli_capture

        canned_payload = {
            "schema": "tls-chameleon.capture/1",
            "endpoint": local_server,
            "captured_at": "2026-08-23T00:00:00+00:00",
            "fingerprint": {
                "name": "cli_capture",
                "tls": {"version": "771", "cipher_ids": [], "ja4": "t13d"},
                "http2": {}, "headers": {},
                "metadata": {"source": "captured", "verified": True},
            },
        }

        class _Result:
            endpoint = local_server
            captured_at = "2026-08-23T00:00:00+00:00"
            raw = {"internal_secret": "hide-me"}

            @staticmethod
            def to_dict():
                return dict(canned_payload)

            fingerprint = type("FP", (), {"to_dict": staticmethod(
                lambda: canned_payload["fingerprint"])})()

        monkeypatch.setattr(cli_capture, "capture",
                            lambda **kw: _Result())
        rc = main(["capture", local_server, "--raw", "--json",
                   "--engine", "httpx"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["fingerprint"]["metadata"]["source"] == "captured"
        assert payload["raw"]["internal_secret"] == "[REDACTED]"

    def test_benchmark_runs_real_measurements(self, capsys):
        # Phase 6: benchmark is no longer a stub; tiny but REAL run.
        rc = main(["benchmark", "--json", "--scenario", "http1",
                   "--requests", "3", "--warmup", "1"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["schema"] == "tls-chameleon.benchmark/2"
        assert payload["status"] == "ok"
        ok_rows = [e for e in payload["scenarios"]["http1"]
                   if e.get("status") == "ok"]
        assert ok_rows and all(row["rps"] > 0 for row in ok_rows)


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

def test_unknown_subcommand_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["definitely-not-a-command"])
    assert exc.value.code == 2


def test_console_entry_registered():
    from tls_chameleon.cli import main as entry

    assert callable(entry)
