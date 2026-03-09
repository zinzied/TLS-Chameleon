import asyncio
import time
from tls_chameleon import AsyncSession, request

async def test_async_features():
    print("=== Testing AsyncSession & Rate-Limiting ===")
    
    # 1. Test rate-limiting and hook
    def retry_hook(attempt, resp, profile):
        print(f"  [Hook] Retry attempt {attempt} with profile {profile}")
        
    start = time.time()
    
    # We set rate_limit=2.0 (2 requests per second, or 1 every 0.5s)
    async with AsyncSession(profile="chrome_130_win11", rate_limit=2.0, on_retry=retry_hook) as session:
        print("  Starting 3 requests (Should take ~1s due to rate limit)")
        
        # Req 1 (0.0s)
        resp1 = await session.get("https://tls.peet.ws/api/all")
        print(f"  Req 1 JSON: {resp1.json().get('tls_version')}")
        
        # Req 2 (0.5s)
        resp2 = await session.get("https://tls.peet.ws/api/all")
        print(f"  Req 2 JSON: {resp2.json().get('tls_version')}")
        
        # Req 3 (1.0s)
        resp3 = await session.get("https://tls.peet.ws/api/all")
        print(f"  Req 3 JSON: {resp3.json().get('tls_version')}")

    elapsed = time.time() - start
    print(f"  Finished in {elapsed:.2f} seconds (Expected ~1.0s+)")
    
    # 2. Test Magnet caching
    print("\n=== Testing Magnet Cached Property ===")
    resp = request("GET", "https://example.com")
    m1 = resp.magnet
    m2 = resp.magnet
    print(f"  Magnet instances identical? {m1 is m2}")

if __name__ == "__main__":
    asyncio.run(test_async_features())
