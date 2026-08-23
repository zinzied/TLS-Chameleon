from tls_chameleon.gen_fingerprint import (
    generate_fingerprint,
    parse_gen_spec,
    resolve_gen_profile,
    is_gen_profile,
)
from tls_chameleon.randomizer import FingerprintRandomizer
from tls_chameleon.profiles import PROFILES, get_profile
from tls_chameleon.fingerprint_gallery import get_profile as gallery_get_profile
from tls_chameleon.client import _DOMAIN_MEMORY, _DOMAIN_MEMORY_MAX, _DOMAIN_MEMORY_LOCK
from tls_chameleon.magnet import Magnet


def test_gen_fingerprint_deterministic():
    fp1 = generate_fingerprint(seed="test_seed_123")
    fp2 = generate_fingerprint(seed="test_seed_123")
    assert fp1.profile["ja3"] == fp2.profile["ja3"]
    assert fp1.profile["ja4"] == fp2.profile["ja4"]
    assert fp1.profile["ciphers"] == fp2.profile["ciphers"]


def test_gen_fingerprint_spec():
    name = "gen://chrome/win10/120/balanced/42"
    assert is_gen_profile(name)
    params = parse_gen_spec(name)
    assert params["family"] == "chrome"
    assert params["major"] == 120
    assert params["os"] == "win10"
    assert params["seed"] == "42"

    p = resolve_gen_profile(name)
    assert "ja3" in p
    assert "ja4" in p
    assert "user_agent" in p


def test_randomizer_cipher_shuffle():
    ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"]
    r = FingerprintRandomizer(PROFILES["chrome_120"])
    res = r._randomize_ciphers(ciphers)
    assert set(res) == set(ciphers)
    assert len(res) == len(ciphers)


def test_domain_memory_bounded():
    with _DOMAIN_MEMORY_LOCK:
        _DOMAIN_MEMORY.clear()
        for i in range(_DOMAIN_MEMORY_MAX + 50):
            domain = f"example{i}.com"
            _DOMAIN_MEMORY[domain] = "chrome_120"
            _DOMAIN_MEMORY.move_to_end(domain)
            while len(_DOMAIN_MEMORY) > _DOMAIN_MEMORY_MAX:
                _DOMAIN_MEMORY.popitem(last=False)
        assert len(_DOMAIN_MEMORY) == _DOMAIN_MEMORY_MAX
        assert "example0.com" not in _DOMAIN_MEMORY
        assert f"example{_DOMAIN_MEMORY_MAX + 49}.com" in _DOMAIN_MEMORY


def test_profile_retrieval():
    assert "chrome_120" in PROFILES
    p = get_profile("chrome_120")
    assert p is not None
    assert "user_agent" in p

    p_gallery = gallery_get_profile("chrome_120")
    assert p_gallery is not None


def test_magnet_deep_extract():
    html = '''
    <html>
        <script>
            const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_match";
            const api_key = "AIzaSyD-1234567890abcdefghijklmnopqrstuv";
        </script>
        <a href="mailto:test@example.com">Contact</a>
        <a href="https://example.com/about">About</a>
    </html>
    '''
    m = Magnet(html)
    assert "test@example.com" in m.emails()
    assert "https://example.com/about" in m.links()
