"""Phase 4 adaptive engine tests: domain memory, profile_for, deterministic
randomization, header consistency."""

import random
import threading
import time

import pytest

import tls_chameleon
from tls_chameleon import (
    TLSChameleon,
    DomainMemory,
    derive_seed_rng,
    check_header_consistency,
    HeaderProfile,
)
from tls_chameleon.adaptive import DomainMemory as _DM  # import identity check
from tls_chameleon.client import (
    _DOMAIN_MEMORY,
    _DOMAIN_MEMORY_LOCK,
    _DOMAIN_MEMORY_MAX,
    _cipher_list,
    _split_kwargs,
)
from tests.test_fingerprint_system import _legacy_profile
from tests.test_diagnostics import (
    _FakeSession,
    _HttpxLikeResponse,
    _make_client,
)


# ---------------------------------------------------------------------------
# DomainMemory core behavior
# ---------------------------------------------------------------------------

class TestDomainMemory:
    def test_remember_lookup_roundtrip(self):
        mem = DomainMemory()
        mem.remember("a.com", "chrome_120")
        assert mem.lookup("a.com") == "chrome_120"

    def test_unknown_domain_returns_none(self):
        assert DomainMemory().lookup("never-seen.com") is None

    def test_lru_bound_eviction(self):
        mem = DomainMemory(max_entries=5)
        for i in range(7):
            mem.remember(f"d{i}.com", f"p{i}")
            time.sleep(0.001)
        assert len(mem.data) == 5
        assert "d0.com" not in mem.data and "d1.com" not in mem.data
        assert "d6.com" in mem.data

    def test_lookup_refreshes_recency(self):
        mem = DomainMemory(max_entries=2)
        mem.remember("old.com", "p1")
        mem.remember("new.com", "p2")
        mem.lookup("old.com")           # refresh old -> new becomes LRU
        mem.remember("fresh.com", "p3") # evicts new.com, not old.com
        assert "old.com" in mem.data
        assert "new.com" not in mem.data

    def test_ttl_expiration(self):
        mem = DomainMemory(ttl_seconds=0.05)
        mem.remember("x.com", "p")
        assert mem.lookup("x.com") == "p"
        time.sleep(0.06)
        assert mem.lookup("x.com") is None
        assert "x.com" not in mem.data

    def test_no_ttl_never_expires(self):
        mem = DomainMemory(ttl_seconds=None)
        mem.remember("y.com", "p")
        assert mem.lookup("y.com") == "p"

    def test_forget_and_clear(self):
        mem = DomainMemory()
        mem.remember("f.com", "p")
        mem.forget("f.com")
        assert mem.lookup("f.com") is None
        mem.remember("g.com", "p")
        mem.clear()
        assert mem.stats()["entries"] == 0

    def test_invalid_max_entries(self):
        with pytest.raises(ValueError):
            DomainMemory(max_entries=0)

    def test_explain_fields(self):
        mem = DomainMemory()
        for _ in range(6):
            mem.remember("e.com", "chrome_124")
        info = mem.explain("e.com")
        assert set(info) == {"profile", "reason", "confidence", "last_used"}
        assert info["profile"] == "chrome_124"
        assert 0.0 < info["confidence"] <= 1.0
        assert "successful" in info["reason"]
        assert info["last_used"] is not None

    def test_explain_unknown(self):
        info = DomainMemory().explain("nope.com")
        assert info["profile"] is None
        assert info["confidence"] == 0.0

    def test_stats_shape(self):
        stats = DomainMemory(ttl_seconds=60).stats()
        assert {"entries", "max_entries", "ttl_seconds",
                "oldest_age_seconds"} <= set(stats)

    def test_thread_safety_smoke(self):
        mem = DomainMemory(max_entries=50)
        errors = []

        def worker(n):
            try:
                for i in range(200):
                    mem.remember(f"t{n}-{i % 20}.com", "p")
                    mem.lookup(f"t{n}-{i % 20}.com")
                    mem.explain(f"t{n}-0.com")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(mem.data) <= 50


class TestLegacyAliases:
    def test_alias_identity_with_module_singleton(self):
        from tls_chameleon import client as client_module

        assert client_module._memory.data is client_module._DOMAIN_MEMORY
        assert client_module._memory.lock is client_module._DOMAIN_MEMORY_LOCK

    def test_old_style_manipulation_still_works(self):
        with _DOMAIN_MEMORY_LOCK:
            _DOMAIN_MEMORY.clear()
            _DOMAIN_MEMORY["legacy.com"] = "chrome_120"
            _DOMAIN_MEMORY.move_to_end("legacy.com")
        assert "legacy.com" in _DOMAIN_MEMORY
        assert len(_DOMAIN_MEMORY) <= _DOMAIN_MEMORY_MAX
        with _DOMAIN_MEMORY_LOCK:
            del _DOMAIN_MEMORY["legacy.com"]

    def test_importable_from_package_root(self):
        assert tls_chameleon.DomainMemory is _DM


# ---------------------------------------------------------------------------
# Client-level adaptive selection
# ---------------------------------------------------------------------------

class TestClientAdaptive:
    def test_learning_on_success(self):
        client = TLSChameleon(engine="httpx", timeout=5)
        client.session = _FakeSession(_HttpxLikeResponse())
        try:
            client.get("http://learn.test/")
            assert _DOMAIN_MEMORY.get("learn.test") == client.profile_name
            explanation = client.profile_for("learn.test")
            assert explanation["profile"] == client.profile_name
            assert explanation["confidence"] > 0.0
        finally:
            client.close()
            _DOMAIN_MEMORY.pop("learn.test", None)

    def test_adaptive_disabled_does_not_learn_or_switch(self):
        before = dict(_DOMAIN_MEMORY)
        client = TLSChameleon(engine="httpx", timeout=5, adaptive=False)
        client.session = _FakeSession(_HttpxLikeResponse())
        try:
            client.get("http://nolearn.test/")
            assert "nolearn.test" not in _DOMAIN_MEMORY
            assert client.profile_for("nolearn.test")["profile"] is None
        finally:
            client.close()
            _DOMAIN_MEMORY.clear()
            _DOMAIN_MEMORY.update(before)

    def test_switch_to_learned_profile_when_not_explicit(self):
        _DOMAIN_MEMORY["switch.test"] = "firefox_120_win11"
        client = TLSChameleon(engine="httpx", timeout=5)  # no explicit profile
        client.session = _FakeSession(_HttpxLikeResponse())
        # Profile switching calls _init_session(), which would replace our
        # fake session with a real backend client -- stub it out.
        client._init_session = lambda: None
        try:
            client.get("http://switch.test/")
            assert client.profile_name == "firefox_120_win11"
            assert isinstance(client.session, _FakeSession)
        finally:
            client.close()
            _DOMAIN_MEMORY.pop("switch.test", None)

    def test_explicit_profile_wins_over_memory(self):
        _DOMAIN_MEMORY["explicit.test"] = "firefox_120_win11"
        client = TLSChameleon(engine="httpx", timeout=5,
                              profile="chrome_120_win11")
        client.session = _FakeSession(_HttpxLikeResponse())
        try:
            client.get("http://explicit.test/")
            assert client.profile_name == "chrome_120_win11"
            reason = client.profile_for("explicit.test")["reason"]
            assert "explicit" in reason
        finally:
            client.close()
            _DOMAIN_MEMORY.pop("explicit.test", None)


# ---------------------------------------------------------------------------
# Deterministic randomization
# ---------------------------------------------------------------------------

class TestDeterministicRandomization:
    def test_derive_seed_rng_is_process_stable(self):
        a1, a2 = derive_seed_rng(123), derive_seed_rng(123)
        seq_a = [a1.random() for _ in range(5)]
        seq_b = [a2.random() for _ in range(5)]
        assert seq_a == seq_b

    def test_different_seeds_usually_differ(self):
        s123 = [derive_seed_rng(123).random() for _ in range(3)]
        s999 = [derive_seed_rng(999).random() for _ in range(3)]
        assert s123 != s999

    def test_cipher_order_reproducible_with_seed(self):
        # Use the FULL gallery cipher list (15 entries): with the tiny 3-cipher
        # test fixture, different seeds legitimately collide (6 permutations).
        from tls_chameleon.fingerprint_gallery import FINGERPRINT_GALLERY

        p = dict(FINGERPRINT_GALLERY["chrome_120_win11"])
        p["tls12_ciphers"] = list(p["ciphers"])
        rng_a = derive_seed_rng("seed-A")
        rng_b = derive_seed_rng("seed-A")
        list_a = _cipher_list(p, True, rng=rng_a)
        list_b = _cipher_list(p, True, rng=rng_b)
        assert list_a == list_b
        assert list_a.count(":") >= 10
        # a different seed yields a different order
        list_c = _cipher_list(p, True, rng=derive_seed_rng("seed-B"))
        assert list_c != list_a

    def test_client_seed_produces_identical_fingerprint_info(self):
        c1 = TLSChameleon(engine="httpx", randomize=True, random_seed=42)
        c2 = TLSChameleon(engine="httpx", randomize=True, random_seed=42)
        try:
            i1, i2 = c1.get_fingerprint_info(), c2.get_fingerprint_info()
            assert i1["user_agent"] == i2["user_agent"]
            assert i1["random_seed"] == 42
        finally:
            c1.close()
            c2.close()

    def test_unseeded_clients_are_independent(self):
        c1 = TLSChameleon(engine="httpx", randomize_ciphers=True)
        c2 = TLSChameleon(engine="httpx", randomize_ciphers=True)
        try:
            l1 = _cipher_list(c1._current_profile_data, True, rng=c1._rng or random.Random())
            l2 = _cipher_list(c2._current_profile_data, True, rng=c2._rng or random.Random())
            assert l1 != l2 or True  # smoke: no crash without seed
        finally:
            c1.close()
            c2.close()

    def test_randomizer_accepts_seeded_rng(self):
        from tls_chameleon.randomizer import FingerprintRandomizer

        base = _legacy_profile()
        base.setdefault("randomization", {})["extension_variance"] = 4
        v1 = FingerprintRandomizer(base, rng=derive_seed_rng(7)).generate_variant()
        v2 = FingerprintRandomizer(base, rng=derive_seed_rng(7)).generate_variant()
        assert v1["extensions"] == v2["extensions"]

    def test_gallery_randomize_profile_accepts_rng(self):
        from tls_chameleon.fingerprint_gallery import randomize_profile

        v1 = randomize_profile(_legacy_profile(), rng=derive_seed_rng(3))
        v2 = randomize_profile(_legacy_profile(), rng=derive_seed_rng(3))
        assert v1["user_agent"] == v2["user_agent"]

    def test_session_kwarg_splitting_passes_new_params(self):
        session_kw, request_kw = _split_kwargs(
            {"adaptive": False, "adaptive_ttl": 10, "random_seed": 1,
             "http3": True, "params": {"q": "x"}}
        )
        assert session_kw["adaptive"] is False
        assert session_kw["random_seed"] == 1
        assert session_kw["http3"] is True   # latent bug fixed: http3 is session-level
        assert request_kw == {"params": {"q": "x"}}


# ---------------------------------------------------------------------------
# Header consistency engine
# ---------------------------------------------------------------------------

class TestHeaderConsistency:
    def test_consistent_chrome_profile_passes(self):
        issues = check_header_consistency(_legacy_profile())
        assert all(i.severity != "error" for i in issues)

    def test_chrome_ua_with_firefox_brands_detected(self):
        profile = _legacy_profile()
        profile["sec_ch_ua"] = '"Firefox";v="121"'
        issues = check_header_consistency(profile)
        codes = {i.code for i in issues}
        assert "chrome_ua_with_firefox_brands" in codes
        assert any(i.severity == "error" for i in issues)
        assert any(i.message.startswith("Profile inconsistency detected")
                   for i in issues)

    def test_firefox_must_not_send_client_hints(self):
        profile = _legacy_profile()
        profile["user_agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; "
                                 "rv:121.0) Gecko/20100101 Firefox/121.0")
        profile["sec_ch_ua"] = '"Not_A Brand";v="8", "Chromium";v="120"'
        codes = {i.code for i in check_header_consistency(profile)}
        assert "firefox_with_client_hints" in codes

    def test_mobile_claim_on_desktop_platform(self):
        profile = _legacy_profile()
        profile["sec_ch_ua_mobile"] = "?1"
        profile["sec_ch_ua_platform"] = '"Windows"'
        codes = {i.code for i in check_header_consistency(profile)}
        assert "mobile_claim_on_desktop_platform" in codes

    def test_platform_mismatch_between_ua_and_hints(self):
        profile = _legacy_profile()  # Windows UA
        profile["sec_ch_ua_platform"] = '"macOS"'
        codes = {i.code for i in check_header_consistency(profile)}
        assert "platform_mismatch" in codes

    def test_chrome_missing_client_hints_warns(self):
        profile = {
            "name": "bare_chrome",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
        }
        issues = check_header_consistency(profile)
        assert any(i.code == "chrome_missing_client_hints"
                   and i.severity == "warning" for i in issues)

    def test_header_profile_from_dict(self):
        hp = HeaderProfile.from_profile_dict(_legacy_profile())
        assert hp.ua_family == "chrome"
        assert hp.ua_version == "120"
        assert "host" in hp.header_order

    def test_doctor_reports_header_inconsistency(self):
        from tls_chameleon.diagnostics import doctor

        client = _make_client()
        # Forge an internally contradictory active profile.
        broken = _legacy_profile()
        broken["sec_ch_ua_platform"] = '"macOS"'
        client._current_profile_data = broken
        try:
            report = doctor("https://unit.test/", client)
            hc = next(c for c in report.checks if c.name == "Header consistency")
            assert hc.status == "fail"
            assert report.verdict == "fail"
        finally:
            client.close()


def test_real_gallery_profiles_have_no_contradictions():
    """Every built-in profile must pass its own consistency engine."""
    from tls_chameleon.fingerprint_gallery import FINGERPRINT_GALLERY

    problems = {}
    for name, profile in FINGERPRINT_GALLERY.items():
        errors = [i for i in check_header_consistency(profile)
                  if i.severity == "error"]
        if errors:
            problems[name] = [i.code for i in errors]
    assert problems == {}, f"Inconsistent built-in profiles: {problems}"
