import argparse
import sys
import os
import random
import time

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from tls_chameleon.client import TLSChameleon


class DebugClient(TLSChameleon):
    def request(self, method: str, url: str, **kwargs):
        original_on_block = self.on_block
        attempt = 0
        while True:
            self.on_block = "none"
            resp = super().request(method, url, **kwargs)
            self.on_block = original_on_block
            code = getattr(resp, "status_code", None)
            blocked = self._is_block(resp)
            proxy = self._current_proxy()
            print(f"attempt={attempt} engine={self.engine} profile={getattr(self, '_profile_name', '')} proxy={proxy} status={code} blocked={blocked}")
            if not blocked or attempt >= self.max_retries:
                return resp
            attempt += 1
            if self.on_block in {"rotate", "both"}:
                self._rotate_profile()
                print(f"rotated profile -> {getattr(self, '_profile_name', '')}")
            if self.on_block in {"proxy", "both"}:
                self._rotate_proxy()
                print(f"rotated proxy -> {self._current_proxy()}")
            delay = self.retry_backoff_base * (2 ** (attempt - 1))
            jitter = random.uniform(0, self.retry_jitter)
            time.sleep(delay + jitter)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("url", nargs="?", default="https://www.cloudflare.com/")
    p.add_argument("--fingerprint", default="chrome_124")
    p.add_argument("--rotate-profiles", default="chrome_124,chrome_120,mobile_safari_17")
    p.add_argument("--proxies-pool", default=None)
    p.add_argument("--max-retries", type=int, default=2)
    p.add_argument("--site", default="cloudflare")
    return p.parse_args()


def main():
    a = parse_args()
    rotate_profiles = [x.strip() for x in a.rotate_profiles.split(",") if x.strip()]
    proxies_pool = None
    if a.proxies_pool:
        proxies_pool = [x.strip() for x in a.proxies_pool.split(",") if x.strip()]
    client = DebugClient(
        fingerprint=a.fingerprint,
        site=a.site,
        rotate_profiles=rotate_profiles,
        on_block="both",
        max_retries=a.max_retries,
        randomize_ciphers=True,
        proxies_pool=proxies_pool,
        http2=True,
    )
    try:
        r = client.get(a.url)
    except Exception as e:
        print("error:", str(e))
        sys.exit(2)
    print("final status:", getattr(r, "status_code", None))
    txt = getattr(r, "text", "") or ""
    print("body:", txt[:500].replace("\n", " "))


if __name__ == "__main__":
    main()

