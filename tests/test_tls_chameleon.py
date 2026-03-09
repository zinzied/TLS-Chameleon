import pytest
from unittest.mock import patch, MagicMock
from tls_chameleon import TLSChameleon, Magnet, ChameleonResponse

def test_magnet_get_forms():
    html = '''
    <form action="/login" method="POST">
        <input type="text" name="username" value="admin">
        <input type="password" name="password">
        <button type="submit">Login</button>
    </form>
    '''
    magnet = Magnet(html)
    forms = magnet.get_forms()
    
    assert len(forms) == 1
    assert forms[0]["action"] == "/login"
    assert forms[0]["method"] == "POST"
    assert "username" in forms[0]["inputs"]
    assert forms[0]["inputs"]["username"] == "admin"
    assert "password" in forms[0]["inputs"]

def test_chameleon_response_magnet_cache():
    class DummyResponse:
        text = "Hello World"
        
    resp = ChameleonResponse(DummyResponse())
    m1 = resp.magnet
    m2 = resp.magnet
    assert m1 is m2 # Should be cached property

def test_tls_chameleon_convenience_kwargs():
    from tls_chameleon import get
    # Test that kwargs don't crash when split between session and request
    with patch("tls_chameleon.client.TLSChameleon.get") as mock_get:
        get("https://example.com", headers={"X-Test": "1"}, timeout=5, params={"q": "1"})
        mock_get.assert_called_once_with("https://example.com", params={"q": "1"}, headers={"X-Test": "1"})

def test_tls_chameleon_is_block_false_positive():
    client = TLSChameleon()
    
    # Page with 200 OK discussing cloudflare should NOT trigger block
    class Fake200Response:
        status_code = 200
        text = "This article discusses Cloudflare security features."
    
    # Page with 403 and block keyword SHOULD trigger block
    class Fake403Response:
        status_code = 403
        text = "error 1020: attention required"
        
    assert client._is_block(Fake200Response()) == False
    assert client._is_block(Fake403Response()) == True
