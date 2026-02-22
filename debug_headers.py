"""
🔍 DEBUG: Check actual headers from website
"""

import requests
import json

def check_headers(url):
    """Check actual headers from a website"""
    
    print(f"\n🔍 Checking headers for: {url}")
    print("="*60)
    
    try:
        # Make request
        response = requests.get(
            url,
            timeout=10,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            allow_redirects=True
        )
        
        print(f"\n📍 Final URL: {response.url}")
        print(f"📍 Status Code: {response.status_code}")
        
        print(f"\n📋 ALL HEADERS RECEIVED:")
        print("-"*60)
        
        for header, value in sorted(response.headers.items()):
            print(f"   {header}: {value[:80]}{'...' if len(value) > 80 else ''}")
        
        # Check security headers specifically
        print(f"\n🔐 SECURITY HEADERS CHECK:")
        print("-"*60)
        
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy", 
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy"
        ]
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        found = 0
        missing = 0
        
        for header in security_headers:
            header_lower = header.lower()
            if header_lower in headers_lower:
                print(f"   ✅ {header}: {headers_lower[header_lower][:60]}...")
                found += 1
            else:
                print(f"   ❌ {header}: NOT FOUND")
                missing += 1
        
        print(f"\n📊 Summary: {found} present, {missing} missing")
        
        # Check for info disclosure
        print(f"\n⚠️ INFORMATION DISCLOSURE:")
        print("-"*60)
        
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        
        for header in disclosure_headers:
            header_lower = header.lower()
            if header_lower in headers_lower:
                print(f"   ⚠️ {header}: {headers_lower[header_lower]}")
            else:
                print(f"   ✅ {header}: Not exposed")
        
        return response.headers
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


if __name__ == "__main__":
    # Test with Google
    print("\n" + "="*60)
    print("🌐 TESTING GOOGLE.COM")
    print("="*60)
    check_headers("https://www.google.com")
    
    print("\n\n" + "="*60)
    print("🌐 TESTING GITHUB.COM")
    print("="*60)
    check_headers("https://github.com")