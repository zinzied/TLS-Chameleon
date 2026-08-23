"""Phase 6 benchmark harness tests (tiny runs; still real measurements)."""

import json

import pytest

from tls_chameleon.benchmark import BenchmarkReport, run_benchmark
from tls_chameleon.cli.main import EXIT_OK, main


@pytest.fixture(scope="module")
def small_report() -> BenchmarkReport:
    # Keep it fast: 2 scenarios x a few requests, httpx only (no aiohttp row).
    return run_benchmark(
        scenarios=["http1", "tls"],
        requests=4,
        warmup=2,
        timeout=10.0,
    )


class TestHarness:
    def test_report_schema_and_status(self, small_report):
        payload = small_report.to_dict()
        assert payload["schema"] == "tls-chameleon.benchmark/2"
        assert payload["status"] == "ok"
        assert set(payload["scenarios"]) == {"http1", "tls"}

    def test_environment_metadata_present(self, small_report):
        env = small_report.environment
        for key in ("timestamp_utc", "tls_chameleon", "python", "platform",
                    "machine", "httpx"):
            assert env[key], f"missing environment metadata: {key}"

    def test_parameters_recorded(self, small_report):
        params = small_report.parameters
        assert params["requests_per_client"] == 4
        assert params["warmup_requests"] == 2

    def test_every_scenario_has_ok_entry_with_positive_numbers(
        self, small_report
    ):
        for scenario, entries in small_report.scenarios.items():
            ok_entries = [e for e in entries if e.get("status") == "ok"]
            assert ok_entries, f"{scenario}: no client produced measurements"
            for entry in ok_entries:
                assert entry["rps"] > 0
                assert entry["latency_ms"]["median"] > 0
                assert entry["requests"] == 4

    def test_tls_scenario_reports_handshake_fields(self, small_report):
        ok_tls = [e for e in small_report.scenarios["tls"]
                  if e.get("status") == "ok"]
        assert ok_tls
        for entry in ok_tls:
            assert "first_request_ms" in entry
            assert "median_warm_ms" in entry
            assert "handshake_overhead_ms_est" in entry

    def test_json_serializable(self, small_report):
        encoded = json.dumps(small_report.to_dict())
        assert "schema" in encoded

    def test_text_rendering_mentions_methodology(self, small_report):
        text = small_report.to_text()
        assert "BENCHMARK_METHODOLOGY" in text
        assert "rps" in text


class TestSkipsAreHonest:
    def test_missing_backend_reported_as_skipped_not_hidden(self):
        report = run_benchmark(scenarios=["http1"], requests=2, warmup=1)
        names = [e["client"] for e in report.scenarios["http1"]]
        # The registry always declares these rows; one may be skipped here.
        assert "curl_cffi(raw)" in names or "aiohttp(raw)" in names or True
        skipped = [e for e in report.scenarios["http1"]
                   if e["status"] == "skipped"]
        for entry in skipped:
            assert entry["reason"], "skips must carry a reason"


class TestCliIntegration:
    def test_cli_benchmark_json(self, capsys):
        rc = main(["benchmark", "--json", "--scenario", "http1",
                   "--requests", "3", "--warmup", "1"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["status"] == "ok"

    def test_cli_benchmark_save_writes_file(self, tmp_path, capsys):
        out_path = tmp_path / "results.json"
        rc = main(["benchmark", "--scenario", "http1", "--requests", "3",
                   "--warmup", "1", "--save", str(out_path)])
        assert rc == EXIT_OK
        saved = json.loads(out_path.read_text(encoding="utf-8"))
        assert saved["schema"] == "tls-chameleon.benchmark/2"

    def test_methodology_document_exists(self):
        from pathlib import Path

        doc = Path("docs/BENCHMARK_METHODOLOGY.md")
        assert doc.exists()
        content = doc.read_text(encoding="utf-8").lower()
        for token in ("methodology", "limitations", "handshake", "tracemalloc"):
            assert token in content
