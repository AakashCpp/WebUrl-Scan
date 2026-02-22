"""
📋 HTTP HEADER ANALYZER - ACCURATE VERSION
Analyzes security headers with proper scoring
"""

import requests
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import sys
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ScanConfig


@dataclass
class SecurityHeader:
    """Security header definition"""
    name: str
    aliases: List[str]
    importance: str  # critical, high, medium, low
    description: str
    weight: int  # Points for scoring


# Security headers with proper weights
SECURITY_HEADERS_CONFIG = [
    SecurityHeader(
        name="Strict-Transport-Security",
        aliases=["strict-transport-security"],
        importance="critical",
        description="Enforces HTTPS connections (HSTS)",
        weight=20
    ),
    SecurityHeader(
        name="Content-Security-Policy",
        aliases=["content-security-policy", "content-security-policy-report-only"],
        importance="critical", 
        description="Prevents XSS and injection attacks",
        weight=20
    ),
    SecurityHeader(
        name="X-Frame-Options",
        aliases=["x-frame-options"],
        importance="high",
        description="Prevents clickjacking attacks",
        weight=15
    ),
    SecurityHeader(
        name="X-Content-Type-Options",
        aliases=["x-content-type-options"],
        importance="high",
        description="Prevents MIME type sniffing",
        weight=15
    ),
    SecurityHeader(
        name="Referrer-Policy",
        aliases=["referrer-policy"],
        importance="medium",
        description="Controls referrer information",
        weight=10
    ),
    SecurityHeader(
        name="Permissions-Policy",
        aliases=["permissions-policy", "feature-policy"],
        importance="medium",
        description="Controls browser features/APIs",
        weight=10
    ),
    SecurityHeader(
        name="X-XSS-Protection",
        aliases=["x-xss-protection"],
        importance="low",
        description="Legacy XSS filter (deprecated in modern browsers)",
        weight=5
    ),
    SecurityHeader(
        name="Cross-Origin-Opener-Policy",
        aliases=["cross-origin-opener-policy"],
        importance="low",
        description="Isolates browsing context",
        weight=5
    ),
]

# Total possible score
MAX_SCORE = sum(h.weight for h in SECURITY_HEADERS_CONFIG)

# Information disclosure headers
INFO_DISCLOSURE_HEADERS = [
    ("server", "Server software", 2),
    ("x-powered-by", "Backend technology", 5),
    ("x-aspnet-version", "ASP.NET version", 5),
    ("x-aspnetmvc-version", "ASP.NET MVC version", 5),
]


@dataclass
class HeaderResult:
    """HTTP header analysis result"""
    url: str = ""
    final_url: str = ""
    status_code: int = 0
    all_headers: Dict = field(default_factory=dict)
    present_headers: List[Dict] = field(default_factory=list)
    missing_headers: List[Dict] = field(default_factory=list)
    partial_headers: List[Dict] = field(default_factory=list)  # Report-only etc.
    info_disclosure: List[Dict] = field(default_factory=list)
    other_issues: List[str] = field(default_factory=list)
    raw_score: int = 0
    final_score: int = 0
    grade: str = "F"
    summary: str = ""


class HeaderAnalyzer:
    """
    Accurate HTTP Header Security Analyzer
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
    
    def analyze(self, url: str) -> HeaderResult:
        """Analyze HTTP headers of a URL"""
        
        result = HeaderResult(url=url)
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=True,
                allow_redirects=True
            )
            
            result.final_url = response.url
            result.status_code = response.status_code
            result.all_headers = dict(response.headers)
            
            # Lowercase headers for comparison
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            # Analyze security headers
            self._analyze_security_headers(result, headers_lower)
            
            # Check information disclosure
            self._check_info_disclosure(result, headers_lower)
            
            # Check other issues
            self._check_other_issues(result, response, headers_lower)
            
            # Calculate final score and grade
            self._calculate_score(result)
            
        except requests.exceptions.SSLError:
            result.other_issues.append("SSL/TLS certificate error")
            result.grade = "F"
            result.final_score = 0
        except requests.exceptions.ConnectionError:
            result.other_issues.append("Connection failed")
            result.grade = "F"
            result.final_score = 0
        except requests.exceptions.Timeout:
            result.other_issues.append("Request timeout")
            result.grade = "F"
            result.final_score = 0
        except Exception as e:
            result.other_issues.append(f"Error: {str(e)[:100]}")
            result.grade = "F"
            result.final_score = 0
        
        return result
    
    def _analyze_security_headers(self, result: HeaderResult, headers_lower: Dict):
        """Check each security header"""
        
        for header_config in SECURITY_HEADERS_CONFIG:
            found = False
            found_value = None
            is_partial = False  # For report-only headers
            
            for alias in header_config.aliases:
                if alias in headers_lower:
                    found = True
                    found_value = headers_lower[alias]
                    
                    # Check if it's report-only (partial implementation)
                    if "report-only" in alias:
                        is_partial = True
                    break
            
            if found:
                header_info = {
                    'name': header_config.name,
                    'value': found_value[:150] if found_value else "",
                    'importance': header_config.importance,
                    'weight': header_config.weight,
                    'is_partial': is_partial
                }
                
                if is_partial:
                    result.partial_headers.append(header_info)
                else:
                    result.present_headers.append(header_info)
            else:
                result.missing_headers.append({
                    'name': header_config.name,
                    'importance': header_config.importance,
                    'description': header_config.description,
                    'weight': header_config.weight
                })
    
    def _check_info_disclosure(self, result: HeaderResult, headers_lower: Dict):
        """Check for information disclosure"""
        
        for header, description, penalty in INFO_DISCLOSURE_HEADERS:
            if header in headers_lower:
                value = headers_lower[header]
                if value:
                    result.info_disclosure.append({
                        'header': header,
                        'value': value,
                        'description': description,
                        'penalty': penalty
                    })
    
    def _check_other_issues(self, result: HeaderResult, response, headers_lower: Dict):
        """Check for other security issues"""
        
        # Not using HTTPS
        if not result.final_url.startswith('https://'):
            result.other_issues.append("Not using HTTPS")
        
        # Wildcard CORS
        acao = headers_lower.get('access-control-allow-origin', '')
        if acao == '*':
            result.other_issues.append("Wildcard CORS (Access-Control-Allow-Origin: *)")
        
        # Check cookies
        for cookie in response.cookies:
            if not cookie.secure and result.final_url.startswith('https://'):
                result.other_issues.append(f"Cookie '{cookie.name}' missing Secure flag")
    
    def _calculate_score(self, result: HeaderResult):
        """Calculate security score and grade"""
        
        score = 0
        
        # Add points for present headers
        for h in result.present_headers:
            score += h['weight']
        
        # Add half points for partial headers (report-only)
        for h in result.partial_headers:
            score += h['weight'] * 0.5
        
        result.raw_score = score
        
        # Deduct for info disclosure
        for d in result.info_disclosure:
            score -= d['penalty']
        
        # Deduct for other issues
        score -= len(result.other_issues) * 3
        
        # Calculate percentage
        percentage = (score / MAX_SCORE) * 100
        percentage = max(0, min(100, percentage))
        
        result.final_score = int(percentage)
        
        # Assign grade
        if percentage >= 90:
            result.grade = "A+"
        elif percentage >= 80:
            result.grade = "A"
        elif percentage >= 70:
            result.grade = "B"
        elif percentage >= 60:
            result.grade = "C"
        elif percentage >= 50:
            result.grade = "D"
        elif percentage >= 30:
            result.grade = "E"
        else:
            result.grade = "F"
        
        # Generate summary
        total_headers = len(SECURITY_HEADERS_CONFIG)
        present = len(result.present_headers)
        partial = len(result.partial_headers)
        missing = len(result.missing_headers)
        
        result.summary = f"{present} present, {partial} partial, {missing} missing out of {total_headers} headers"


def test_header_analyzer():
    """Test with real websites"""
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           📋 HEADER ANALYZER - ACCURACY TEST                  ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    analyzer = HeaderAnalyzer()
    
    targets = [
        ("https://www.google.com", "Google - Large tech company"),
        ("https://github.com", "GitHub - Developer platform"),
        ("https://cloudflare.com", "Cloudflare - Security company"),
    ]
    
    for url, description in targets:
        print(f"\n{'='*70}")
        print(f"🌐 {description}")
        print(f"   URL: {url}")
        print("="*70)
        
        result = analyzer.analyze(url)
        
        # Grade icon
        grade_icons = {
            'A+': '🟢', 'A': '🟢', 'B': '🟢',
            'C': '🟡', 'D': '🟠',
            'E': '🔴', 'F': '🔴'
        }
        icon = grade_icons.get(result.grade, '⚪')
        
        print(f"""
   ┌────────────────────────────────────────────┐
   │  Grade: {icon} {result.grade}                              │
   │  Score: {result.final_score}/100                          │
   │  {result.summary:<40} │
   └────────────────────────────────────────────┘
        """)
        
        # Present headers
        if result.present_headers:
            print(f"   ✅ PRESENT HEADERS ({len(result.present_headers)}):")
            for h in result.present_headers:
                importance_icon = "🔴" if h['importance'] == 'critical' else "🟠" if h['importance'] == 'high' else "🟡"
                value_short = h['value'][:40] + "..." if len(h['value']) > 40 else h['value']
                print(f"      {importance_icon} {h['name']}")
                print(f"         └─ {value_short}")
        
        # Partial headers
        if result.partial_headers:
            print(f"\n   🟡 PARTIAL HEADERS ({len(result.partial_headers)}):")
            for h in result.partial_headers:
                print(f"      ⚠️ {h['name']} (report-only mode)")
        
        # Missing headers
        if result.missing_headers:
            print(f"\n   ❌ MISSING HEADERS ({len(result.missing_headers)}):")
            for h in result.missing_headers[:5]:  # Show max 5
                importance_icon = "🔴" if h['importance'] == 'critical' else "🟠" if h['importance'] == 'high' else "🟡"
                print(f"      {importance_icon} {h['name']} ({h['importance']})")
            if len(result.missing_headers) > 5:
                print(f"      ... and {len(result.missing_headers) - 5} more")
        
        # Info disclosure
        if result.info_disclosure:
            print(f"\n   ⚠️ INFORMATION DISCLOSURE ({len(result.info_disclosure)}):")
            for d in result.info_disclosure:
                print(f"      • {d['header']}: {d['value']}")
        
        # Other issues
        if result.other_issues:
            print(f"\n   🚨 OTHER ISSUES ({len(result.other_issues)}):")
            for issue in result.other_issues:
                print(f"      • {issue}")
    
    print("\n" + "="*70)
    print("✅ Test complete!")
    print("="*70)


if __name__ == "__main__":
    test_header_analyzer()