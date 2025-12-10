import argparse
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from tls_chameleon import TLSChameleon


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("url", nargs="?", default="https://httpbin.org/get")
    p.add_argument("--fingerprint", default="chrome_120")
    p.add_argument("--site", default=None)
    p.add_argument("--on-block", dest="on_block", default="rotate")
    p.add_argument("--max-retries", dest="max_retries", type=int, default=2)
    p.add_argument("--randomize-ciphers", action="store_true")
    p.add_argument("--proxies-pool", dest="proxies_pool", default=None)
    p.add_argument("--header-order", dest="header_order", default=None)
    p.add_argument("--http2", action="store_true")
    return p.parse_args()


def main():
    a = parse_args()
    proxies_pool = None
    if a.proxies_pool:
        proxies_pool = [x.strip() for x in a.proxies_pool.split(",") if x.strip()]
    header_order = None
    if a.header_order:
        header_order = [x.strip() for x in a.header_order.split(",") if x.strip()]
    client = TLSChameleon(
        fingerprint=a.fingerprint,
        site=a.site,
        on_block=a.on_block,
        max_retries=a.max_retries,
        randomize_ciphers=a.randomize_ciphers,
        proxies_pool=proxies_pool,
        header_order=header_order,
        http2=a.http2,
    )
    try:
        r = client.get(a.url)
    except Exception as e:
        print("error:", str(e))
        sys.exit(2)
    print("status:", getattr(r, "status_code", None))
    txt = getattr(r, "text", "") or ""
    print("body:", txt[:500].replace("\n", " "))
    print("engine:", client.engine)
    print("profile:", getattr(client, "_profile_name", ""))
    print("user_agent:", client.headers.get("User-Agent"))


if __name__ == "__main__":
    main()
