import tls_chameleon
import time

def test_persistence():
    print("Testing Session Persistence...")
    
    # 1. Instantiate the client (Session)
    # Using 'chrome_120' which maps to curl_cffi if available or httpx
    with tls_chameleon.Session(fingerprint="chrome_120") as client:
        print(f"Engine used: {client.engine}")
        
        # 2. Make a request that sets a cookie
        print("Request 1: Setting cookie...")
        try:
            # Google sets cookies on first visit
            resp1 = client.get("https://www.google.com")
            print(f"Resp1 Status: {resp1.status_code}")
            print(f"Resp1 Cookies: {len(client.session.cookies)} cookies found.")
        except Exception as e:
            print(f"Request 1 failed: {e}")
            return

        # 3. Make a second request to check if the cookie is sent back
        # We can't easily see sent cookies on client side in this test without a debug echo server,
        # but we can check if the Session object HAS cookies.
        print("Request 2: Checking session cookies...")
        if len(client.session.cookies) > 0:
             print("SUCCESS: Session has cookies!")
             for c in client.session.cookies:
                 print(f" - {c.name}")
        else:
             print("FAILURE: No cookies in session.")

if __name__ == "__main__":
    test_persistence()
