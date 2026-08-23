import sys
import traceback
from tls_chameleon import TLSSession

URL = "https://cloudflare-quic.com/"

try:
    print("Creating session with http3=True, engine='httpx'")
    s = TLSSession(engine='httpx', http3=True, timeout=10)
    print("Session created. get_fingerprint_info:", s.get_fingerprint_info())
    print(f"Requesting {URL} ...")
    resp = s.get(URL, timeout=10)
    print("Status code:", getattr(resp, 'status_code', None))
    # httpx.Response exposes http_version
    print("HTTP version:", getattr(resp, 'http_version', None))
    print("Response headers sample:", dict(list(getattr(resp, 'headers', {}).items())[:5]))
    s.close()
except Exception as e:
    print("Error during integration test:")
    traceback.print_exc()
    sys.exit(2)

print("Done")
