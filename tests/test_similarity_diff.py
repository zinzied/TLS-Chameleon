"""Phase 2 similarity / diff / capture tests."""

import json

import pytest

from tls_chameleon.fingerprint import (
    Fingerprint,
    FingerprintSimilarity,
    SimilarityWeights,
    diff_fingerprints,
)
from tls_chameleon.fingerprint.adapter import fingerprint_from_legacy
from tests.test_fingerprint_system import CHROME_120_JA3, _legacy_profile

FIREFOX_JA3 = (
    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161"
    "-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"
)


def _firefox_profile() -> dict:
    profile = _legacy_profile()
    profile["name"] = "firefox_120_win11"
    profile["ja3"] = FIREFOX_JA3
    profile["header_case"] = "title"
    profile["http2_settings"] = {
        "HEADER_TABLE_SIZE": 65536,
        "ENABLE_PUSH": 0,
        "INITIAL_WINDOW_SIZE": 131072,  # differs from chrome
    }
    return profile


@pytest.fixture()
def chrome_fp() -> Fingerprint:
    return fingerprint_from_legacy(_legacy_profile())


@pytest.fixture()
def firefox_fp() -> Fingerprint:
    return fingerprint_from_legacy(_firefox_profile())


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------

class TestSimilarity:
    def test_identical_scores_100(self, chrome_fp):
        clone = Fingerprint.from_dict(chrome_fp.to_dict())
        result = FingerprintSimilarity().compare(chrome_fp, clone)
        assert result.total == 100.0
        assert result.changed_fields == []

    def test_different_profiles_score_below_100(self, chrome_fp, firefox_fp):
        result = FingerprintSimilarity().compare(chrome_fp, firefox_fp)
        assert 0.0 <= result.total < 100.0
        assert {"tls", "http2", "headers"} <= set(result.layers)

    def test_weights_are_respected(self, chrome_fp, firefox_fp):
        # TLS-only comparison must equal the TLS layer score of the full one.
        tls_only = FingerprintSimilarity(SimilarityWeights(tls=1.0, http2=0.0, headers=0.0))
        balanced = FingerprintSimilarity(SimilarityWeights())
        r_tls = tls_only.compare(chrome_fp, firefox_fp)
        r_all = balanced.compare(chrome_fp, firefox_fp)
        assert abs(r_tls.total - r_all.layers["tls"]) < 0.15
        assert r_tls.total != r_all.total

    def test_explanation_is_actionable(self, chrome_fp, firefox_fp):
        result = FingerprintSimilarity().compare(chrome_fp, firefox_fp)
        assert any("SETTINGS" in line for line in result.explanation)
        assert any("casing" in line.lower() for line in result.explanation)

    def test_result_is_json_serializable(self, chrome_fp, firefox_fp):
        result = FingerprintSimilarity().compare(chrome_fp, firefox_fp)
        payload = json.dumps(result.to_dict())
        assert "total" in payload


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

class TestDiff:
    def test_text_output_structure(self, chrome_fp, firefox_fp):
        report = diff_fingerprints(chrome_fp, firefox_fp)
        text = report.to_text()
        for token in ("TLS", "Cipher suites", "DIFFERENT", "HTTP/2", "Headers",
                      "Overall similarity"):
            assert token in text

    def test_identical_reports_same(self, chrome_fp):
        clone = Fingerprint.from_dict(chrome_fp.to_dict())
        report = diff_fingerprints(chrome_fp, clone)
        verdicts = [v.same for section in report.sections.values() for v in section]
        assert all(verdicts), "identical fingerprints must be SAME on every field"
        assert report.similarity == 100.0

    def test_machine_readable_dict(self, chrome_fp, firefox_fp):
        data = diff_fingerprints(chrome_fp, firefox_fp).to_dict()
        assert data["a"] == "chrome_120_win11"
        assert data["b"] == "firefox_120_win11"
        assert isinstance(data["similarity"], float)
        assert {"TLS", "HTTP/2", "Headers"} <= set(data["sections"])

    def test_ja4_row_appears_when_present(self, chrome_fp, firefox_fp):
        report = diff_fingerprints(chrome_fp, firefox_fp)
        labels = [v.label for v in report.sections["TLS"]]
        assert "JA4" in labels


# ---------------------------------------------------------------------------
# Capture (mocked endpoint -- no network access in unit tests)
# ---------------------------------------------------------------------------

PEET_LIKE_RESPONSE = {
    "ip": "203.0.113.7",
    "http_version": "h2",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
    "tls": {
        "ja3": CHROME_120_JA3,
        "ja3_hash": "cd08e31494f9531f560d64c695473da9",
        "ja4": "t13d1516h2_8daaf6152771_bba078b4bd11",
        "alpn": ["h2", "http/1.1"],
    },
    "h2": {
        "fingerprint": {
            "sent_settings": {"HEADER_TABLE_SIZE": 65536, "ENABLE_PUSH": 0},
        },
    },
}


class _FakeResponse:
    def __init__(self, payload=None, status_code=200, text_override=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else PEET_LIKE_RESPONSE
        self._text_override = text_override

    @property
    def text(self):
        if self._text_override is not None:
            return self._text_override
        return json.dumps(self._payload)


class _FakeSession:
    def __init__(self, response):
        self._response = response
        self.closed = False

    def request(self, method, url, **kwargs):
        assert method == "GET"
        return self._response

    def close(self):
        self.closed = True


class TestCapture:
    def test_capture_maps_echo_response(self):
        from tls_chameleon.fingerprint import capture

        session = _FakeSession(_FakeResponse())
        result = capture(session=session, name="mocked")

        fp = result.fingerprint
        assert fp.tls.ja3_hash == "cd08e31494f9531f560d64c695473da9"
        assert fp.metadata.source == "captured"
        assert fp.metadata.verified is True
        assert fp.metadata.captured_at  # timestamp present for captures
        assert fp.http2.settings["HEADER_TABLE_SIZE"] == 65536
        assert fp.user_agent.startswith("Mozilla/5.0")

    def test_capture_rejects_http_error(self):
        from tls_chameleon.fingerprint import capture

        session = _FakeSession(_FakeResponse(status_code=403))
        with pytest.raises(RuntimeError, match="403"):
            capture(session=session)

    def test_capture_rejects_non_json(self):
        from tls_chameleon.fingerprint import capture

        session = _FakeSession(_FakeResponse(text_override="<html>nope</html>"))
        with pytest.raises(ValueError, match="valid JSON"):
            capture(session=session)

    def test_capture_result_serializable(self):
        from tls_chameleon.fingerprint import capture

        result = capture(session=_FakeSession(_FakeResponse()), name="mocked")
        data = result.to_dict()
        assert data["schema"] == "tls-chameleon.capture/1"
        assert data["fingerprint"]["metadata"]["source"] == "captured"

    def test_capture_validates_clean(self):
        from tls_chameleon.fingerprint import capture, validate_fingerprint

        result = capture(session=_FakeSession(_FakeResponse()), name="mocked")
        errors = [
            i for i in validate_fingerprint(result.fingerprint) if i.severity == "error"
        ]
        assert errors == []
