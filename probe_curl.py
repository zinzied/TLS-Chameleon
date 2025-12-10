from curl_cffi import requests
try:
    s = requests.Session()
    print("Session created")
    # Try passing curl_options to request
    try:
        s.get("https://example.com", curl_options={})
        print("Success: curl_options accepted")
    except TypeError as e:
        print(f"Failure: {e}")
except Exception as e:
    print(f"General Failure: {e}")
