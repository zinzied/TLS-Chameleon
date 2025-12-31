"""
TLS-Chameleon v2.0 - Advanced Fingerprinting Example
=====================================================

This example demonstrates the new v2.0 features:
- Selecting from 30+ browser profiles
- Fingerprint randomization
- HTTP/2 priority simulation
- Getting fingerprint info for debugging
"""

from tls_chameleon import (
    TLSSession,  # New recommended class name
    list_available_profiles,
    get_profile,
    get_profiles_by_browser,
    get_profiles_by_os,
    FingerprintRandomizer,
)


def demo_profile_selection():
    """Demonstrate the new profile selection API."""
    print("=" * 60)
    print("Profile Selection Demo")
    print("=" * 60)
    
    # List all available profiles
    profiles = list_available_profiles()
    print(f"\n📚 Available profiles: {len(profiles)} total")
    print(f"   First 10: {profiles[:10]}")
    
    # Get profiles by browser
    chrome_profiles = get_profiles_by_browser("chrome")
    firefox_profiles = get_profiles_by_browser("firefox")
    safari_profiles = get_profiles_by_browser("safari")
    
    print(f"\n🌐 Chrome profiles: {len(chrome_profiles)}")
    print(f"   {chrome_profiles[:5]}...")
    print(f"🦊 Firefox profiles: {len(firefox_profiles)}")
    print(f"🍎 Safari profiles: {len(safari_profiles)}")
    
    # Get profiles by OS
    win11_profiles = get_profiles_by_os("win11")
    linux_profiles = get_profiles_by_os("linux")
    macos_profiles = get_profiles_by_os("macos")
    
    print(f"\n💻 Windows 11 profiles: {len(win11_profiles)}")
    print(f"🐧 Linux profiles: {len(linux_profiles)}")
    print(f"🍏 macOS profiles: {len(macos_profiles)}")


def demo_new_api():
    """Demonstrate the new TLSSession API."""
    print("\n" + "=" * 60)
    print("New TLSSession API Demo")
    print("=" * 60)
    
    # Dream API from the proposal - now real!
    session = TLSSession(
        profile='chrome_120_linux',  # Specific profile
        randomize=True,              # Enable fingerprint randomization
        http2_priority='chrome'      # Match HTTP/2 behavior
    )
    
    # Get fingerprint info for debugging
    info = session.get_fingerprint_info()
    print(f"\n🔍 Fingerprint Info:")
    print(f"   Profile: {info['profile_name']}")
    print(f"   User-Agent: {info['user_agent'][:60]}...")
    print(f"   JA3 Hash: {info.get('ja3_hash', 'N/A')}")
    print(f"   Impersonate: {info['impersonate']}")
    print(f"   Randomized: {info['randomized']}")
    print(f"   HTTP/2 Priority: {info['http2_priority']}")
    
    # Make a request
    print(f"\n📡 Making request...")
    try:
        response = session.get("https://httpbin.org/headers")
        if response.status_code == 200:
            headers = response.json().get("headers", {})
            print(f"   Status: {response.status_code} ✓")
            print(f"   Server saw User-Agent: {headers.get('User-Agent', 'N/A')[:50]}...")
        else:
            print(f"   Status: {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    finally:
        session.close()


def demo_randomization():
    """Demonstrate fingerprint randomization."""
    print("\n" + "=" * 60)
    print("Fingerprint Randomization Demo")
    print("=" * 60)
    
    # Get a profile
    base_profile = get_profile("chrome_124_win11")
    if not base_profile:
        print("Profile not found")
        return
    
    print(f"\n📋 Base profile: chrome_124_win11")
    print(f"   Base UA: {base_profile.get('user_agent', '')[:60]}...")
    
    # Create randomized variants
    randomizer = FingerprintRandomizer(base_profile)
    print(f"\n🎲 Generating 3 randomized variants:")
    
    for i in range(3):
        variant = randomizer.generate_variant()
        ua = variant.get("user_agent", "")
        print(f"   Variant {i+1}: {ua[40:80]}...")


def demo_multi_os():
    """Demonstrate multi-OS profile usage."""
    print("\n" + "=" * 60)
    print("Multi-OS Profile Demo")
    print("=" * 60)
    
    platforms = [
        ("chrome_124_win11", "Windows 11"),
        ("chrome_124_win10", "Windows 10"),
        ("chrome_124_linux", "Linux"),
        ("chrome_124_macos", "macOS"),
        ("chrome_android_124", "Android"),
    ]
    
    print(f"\n🖥️ Chrome 124 across platforms:")
    for profile_name, platform_label in platforms:
        profile = get_profile(profile_name)
        if profile:
            ua = profile.get("user_agent", "N/A")
            # Extract OS part
            os_part = ua.split(")")[0].split("(")[-1] if "(" in ua else "N/A"
            print(f"   {platform_label:12} → {os_part[:40]}...")


def main():
    """Run all demos."""
    print("\n🦎 TLS-Chameleon v2.0 Demo\n")
    
    demo_profile_selection()
    demo_new_api()
    demo_randomization()
    demo_multi_os()
    
    print("\n" + "=" * 60)
    print("✅ Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
