"""Phase 2 fingerprint system tests: model, adapter, registry, validator."""

import hashlib

import pytest

from tls_chameleon.fingerprint import (
    Fingerprint,
    FingerprintRegistry,
    Metadata,
    TLSFingerprint,
    validate_fingerprint,
    validate_profile_dict,
)
from tls_chameleon.fingerprint.adapter import (
    fingerprint_from_legacy,
    fingerprint_to_legacy,
)


# ---------------------------------------------------------------------------
# Model / JA3
# ---------------------------------------------------------------------------

class TestTLSFingerprint:
    def test_ja3_roundtrip_and_hash(self):
        ja3 = "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"
        tls = TLSFingerprint(
            version="771",
            cipher_ids=[4865, 4866, 4867],
            extension_ids=[0, 23, 65281, 10, 11],
            curve_ids=[29, 23, 24],
            point_format_ids=[0],
        )
        assert tls.ja3 == ja3
        assert tls.ja3_hash == hashlib.md5(ja3.encode()).hexdigest()

    def test_from_dict_roundtrip(self):
        tls = TLSFingerprint(
            version="771",
            cipher_ids=[4865],
            extension_ids=[0],
            curve_ids=[29],
            point_format_ids=[0],
            ja4="t13d1516h2_8daaf6152771_bba078b4bd11",
            alpn=["h2", "http/1.1"],
        )
        restored = TLSFingerprint.from_dict(tls.to_dict())
        assert restored.ja3 == tls.ja3
        assert restored.ja4 == tls.ja4
        assert restored.alpn == tls.alpn


# ---------------------------------------------------------------------------
# Adapter: legacy gallery dicts -> model
# ---------------------------------------------------------------------------

CHROME_120_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172"
    "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,"
    "29-23-24,0"
)
CHROME_120_HASH = "cd08e31494f9531f560d64c695473da9"


def _legacy_profile() -> dict:
    return {
        "name": "chrome_120_win11",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "ja3": CHROME_120_JA3,
        "ja3_hash": CHROME_120_HASH,
        "ja4": "t13d1516h2_8daaf6152771_bba078b4bd11",
        "ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
        "http2_settings": {"HEADER_TABLE_SIZE": 65536, "ENABLE_PUSH": 0},
        "header_order": ["host", "user-agent", "accept"],
        "header_case": "lower",
    }


class TestAdapter:
    def test_parse_preserves_ja3(self):
        fp = fingerprint_from_legacy(_legacy_profile())
        # The canonical reconstruction must equal the stored string.
        assert fp.tls.ja3 == CHROME_120_JA3
        assert fp.tls.ja3_hash == CHROME_120_HASH
        assert fp.metadata.browser == "chrome"

    def test_http2_and_headers_mapped(self):
        fp = fingerprint_from_legacy(_legacy_profile())
        assert fp.http2.settings["HEADER_TABLE_SIZE"] == 65536
        assert fp.headers.order[:2] == ["host", "user-agent"]
        assert fp.headers.case == "lower"

    def test_gen_profiles_are_synthetic(self):
        profile = _legacy_profile()
        fp = fingerprint_from_legacy(profile, name="gen://chrome/win11/124/balanced/7")
        assert fp.metadata.source == "synthetic"

    def test_gallery_profile_is_documented_not_verified(self):
        fp = fingerprint_from_legacy(_legacy_profile(), name="chrome_120_win11")
        assert fp.metadata.source == "documented"
        assert fp.metadata.verified is False

    def test_to_legacy_roundtrip_has_ja3(self):
        fp = fingerprint_from_legacy(_legacy_profile())
        legacy = fingerprint_to_legacy(fp)
        assert legacy["ja3"] == CHROME_120_JA3
        assert legacy["ja3_hash"] == CHROME_120_HASH
        assert "ciphers" in legacy

    def test_full_model_json_roundtrip(self):
        fp = fingerprint_from_legacy(_legacy_profile())
        restored = Fingerprint.from_dict(fp.to_dict())
        assert restored.to_dict() == fp.to_dict()

    def test_non_numeric_ja3_tokens_kept_in_extra(self):
        profile = _legacy_profile()
        profile["ja3"] = "771,4865-grease_x,0-23,29,0"  # invalid token
        fp = fingerprint_from_legacy(profile)
        assert "ja3_raw" in fp.extra


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_builtin_lookup(self):
        reg = FingerprintRegistry()
        names = reg.list()
        assert names, "built-in gallery must be present"
        fp = reg.get("chrome_120_win11")
        assert fp.name == "chrome_120_win11"
        assert fp.tls.ja3_hash == CHROME_120_HASH

    def test_get_unknown_raises_keyerror(self):
        with pytest.raises(KeyError):
            FingerprintRegistry().get("does_not_exist_123")

    def test_add_get_remove_custom(self):
        reg = FingerprintRegistry(include_builtin=False)
        fp = fingerprint_from_legacy(_legacy_profile(), name="my_custom")
        reg.add(fp)
        assert reg.get("my_custom").name == "my_custom"
        with pytest.raises(ValueError):
            reg.add(fp)  # duplicate without overwrite
        reg.add(fp, overwrite=True)
        reg.remove("my_custom")
        with pytest.raises(KeyError):
            reg.remove("my_custom")

    def test_cannot_remove_builtin(self):
        reg = FingerprintRegistry()
        if not reg.list():
            pytest.skip("no builtins")
        builtin_name = reg.list()[0]
        with pytest.raises(ValueError):
            reg.remove(builtin_name)

    def test_search_by_browser_and_source(self):
        reg = FingerprintRegistry()
        chromes = reg.search(browser="chrome")
        assert chromes
        assert all(fp.metadata.browser == "chrome" for fp in chromes)

    def test_export_import_roundtrip(self, tmp_path):
        src = FingerprintRegistry(include_builtin=False)
        src.add(fingerprint_from_legacy(_legacy_profile(), name="round_trip_me"))
        path = tmp_path / "reg.json"
        src.export(path)

        dst = FingerprintRegistry(include_builtin=False)
        count = dst.import_(path)
        assert count == 1
        assert dst.get("round_trip_me").tls.ja3_hash == CHROME_120_HASH


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestValidator:
    def test_valid_gallery_profile_passes(self):
        issues = validate_profile_dict(_legacy_profile())
        errors = [i for i in issues if i.severity == "error"]
        assert errors == []

    def test_duplicate_extensions_rejected(self):
        fp = fingerprint_from_legacy(_legacy_profile(), name="dupe")
        fp.tls.extension_ids.append(23)  # already present
        codes = {i.code for i in validate_fingerprint(fp)}
        assert "duplicate_extension_ids" in codes

    def test_empty_ciphers_rejected(self):
        fp = fingerprint_from_legacy({"name": "empty"}, name="empty")
        fp.tls.cipher_ids = []
        codes = {i.code for i in validate_fingerprint(fp)}
        assert "no_ciphers" in codes

    def test_tls13_cipher_with_old_version_rejected(self):
        fp = fingerprint_from_legacy({"name": "old"}, name="old")
        fp.tls.version = "770"  # TLS 1.1 record version
        fp.tls.cipher_ids = [4865]
        codes = {i.code for i in validate_fingerprint(fp)}
        assert "tls13_ciphers_with_old_version" in codes

    def test_synthetic_never_verified(self):
        fp = fingerprint_from_legacy(
            _legacy_profile(), name="gen://chrome/win11/124/balanced/1"
        )
        fp.metadata.verified = True
        codes = {i.code for i in validate_fingerprint(fp)}
        assert "synthetic_marked_verified" in codes

    def test_unknown_source_rejected(self):
        with pytest.raises(ValueError):
            Metadata(source="leaked_from_mars")

    def test_capture_without_timestamp_warns(self):
        fp = fingerprint_from_legacy(_legacy_profile(), name="cap")
        fp.metadata.source = "captured"
        fp.metadata.captured_at = None
        issues = validate_fingerprint(fp)
        assert any(i.code == "capture_missing_timestamp" for i in issues)
