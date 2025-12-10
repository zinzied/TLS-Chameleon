from curl_cffi import requests

print("Probing Session init...")
try:
    s = requests.Session(curl_options={})
    print("Success: Session init accepts curl_options")
except TypeError as e:
    print(f"Failure Session init: {e}")
