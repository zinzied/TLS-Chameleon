from curl_cffi import requests
print("Probing top-level request...")
try:
    requests.get("https://example.com", curl_options={})
    print("Success: top-level request accepts curl_options")
except TypeError as e:
    print(f"Failure top-level: {e}")
