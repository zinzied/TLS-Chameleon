"""Phase 3 redaction tests."""

import pytest

from tls_chameleon.security.redaction import (
    REDACTED,
    is_sensitive_header,
    redact_headers,
    redact_mapping,
    redact_url,
)


class TestHeaderRedaction:
    def test_authorization_redacted(self):
        out = redact_headers({"Authorization": "Bearer abc123", "Accept": "text/html"})
        assert out["Authorization"] == REDACTED
        assert out["Accept"] == "text/html"

    @pytest.mark.parametrize(
        "name",
        [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "proxy-authorization",
            "Proxy-Authorization",
            "cookie",
            "Cookie",
            "set-cookie",
            "Set-Cookie",
            "x-api-key",
            "X-API-Key",
            "api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token",
            "x-security-token",
            "password",
            "X-Secret",
        ],
    )
    def test_sensitive_names(self, name):
        assert is_sensitive_header(name) is True

    @pytest.mark.parametrize("name", ["accept", "content-type", "user-agent",
                                      "host", "accept-language", "etag"])
    def test_benign_names(self, name):
        assert is_sensitive_header(name) is False

    def test_names_preserved_values_replaced(self):
        headers = {"cookie": "session=xyz", "content-length": "5"}
        out = redact_headers(headers)
        assert list(out.keys()) == ["cookie", "content-length"]
        assert out["cookie"] == REDACTED
        assert out["content-length"] == "5"

    def test_none_returns_empty(self):
        assert redact_headers(None) == {}


class TestDeepRedaction:
    def test_nested_credentials(self):
        data = {
            "url": "https://example.com",
            "auth": {"username": "bob", "password": "hunter2"},
            "meta": {"api_key": "AIza...", "note": "safe"},
            "items": [{"access_token": "t0k3n"}, {"plain": 1}],
        }
        out = redact_mapping(data)
        assert out["auth"]["password"] == REDACTED
        assert out["auth"]["username"] == "bob"
        assert out["meta"]["api_key"] == REDACTED
        assert out["meta"]["note"] == "safe"
        assert out["items"][0]["access_token"] == REDACTED
        assert out["items"][1]["plain"] == 1

    def test_original_untouched(self):
        data = {"password": "keep-me-original"}
        redact_mapping(data)
        assert data["password"] == "keep-me-original"

    def test_tuples_and_scalars(self):
        out = redact_mapping(({"secret": 1}, "ok", [42]))
        assert out[0]["secret"] == REDACTED
        assert out[1] == "ok"
        assert out[2] == [42]

    def test_json_serializable_output(self):
        import json

        data = {"authorization": "Bearer x", "nested": {"token": ["a", "b"]}}
        payload = json.dumps(redact_mapping(data))
        assert "Bearer" not in payload


class TestUrlRedaction:
    def test_userinfo_stripped(self):
        url = "http://user:pass@example.com/path?q=1#frag"
        assert redact_url(url) == "http://example.com/path?q=1#frag"

    def test_plain_url_unchanged(self):
        url = "https://example.com/a?b=c"
        assert redact_url(url) == url

    def test_port_preserved(self):
        assert redact_url("http://u:p@example.com:8080/") == "http://example.com:8080/"
