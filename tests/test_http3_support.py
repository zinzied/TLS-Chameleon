import pytest

try:
    import httpx
    has_httpx = True
except Exception:
    has_httpx = False

http3_supported = False
if has_httpx:
    # Newer httpx may report http3 via attempting to construct the client
    try:
        c = httpx.Client()
        # We can't reliably detect support without extras; rely on runtime skip if not available
        http3_supported = True
    except Exception:
        http3_supported = False


@pytest.mark.skipif(not has_httpx or not http3_supported, reason="httpx/http3 not available")
def test_http3_flag_does_not_crash():
    # This is an integration-style smoke test that only asserts the library can be initialized
    from tls_chameleon import TLSSession

    # Don't actually hit the network in CI by default; this test only ensures construction works
    s = TLSSession(engine='httpx', http3=True)
    assert hasattr(s, 'session')
    # Close to avoid warnings
    s.close()
