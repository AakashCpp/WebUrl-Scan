"""
🔍 VULNERABILITY SCANNER - FIXED VERSION
Reduced false positives
"""

import requests
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SQLI_PAYLOADS, XSS_PAYLOADS, SENSITIVE_FILES, ScanConfig


@dataclass
class VulnResult:
    """Vulnerability scan result"""
    url: str = ""
    vulnerabilities: List[Dict] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    forms_found: int = 0
    inputs_tested: int = 0
    risk_score: int = 0


class VulnerabilityScanner:
    """
    Vulnerability Scanner - Fixed version with reduced false positives
    """
    
    def __init__(self, timeout: int = ScanConfig.READ_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ScanConfig.USER_AGENT
        })
        self.session.verify = False
        
        # Store baseline response for comparison
        self.baseline_response = None
        self.baseline_length = 0
    
    def scan(self, url: str) -> VulnResult:
        """Run vulnerability scan with reduced false positives"""
        
        result = VulnResult(url=url)
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        print(f"\n🔍 Scanning for vulnerabilities: {url}")
        
        # Get baseline response (for comparison)
        self._get_baseline(url)
        
        # Check for sensitive files
        print("   📁 Checking sensitive files...")
        result.sensitive_files = self._check_sensitive_files(url)
        
        # Test for SQL Injection
        print("   💉 Testing SQL Injection...")
        sqli_vulns = self._test_sqli(url)
        result.vulnerabilities.extend(sqli_vulns)
        
        # Test for XSS
        print("   ⚡ Testing XSS...")
        xss_vulns = self._test_xss(url)
        result.vulnerabilities.extend(xss_vulns)
        
        # Test for open redirects (FIXED)
        print("   🔀 Testing Open Redirects...")
        redirect_vulns = self._test_open_redirect(url)
        result.vulnerabilities.extend(redirect_vulns)
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)
        
        return result
    
    def _get_baseline(self, url: str):
        """Get baseline response for false positive detection"""
        try:
            # Request a definitely non-existent page
            random_path = f"{url.rstrip('/')}/nonexistent_page_12345_xyz"
            response = self.session.get(random_path, timeout=self.timeout)
            self.baseline_response = response
            self.baseline_length = len(response.content)
        except:
            self.baseline_length = 0
    
    def _is_soft_404(self, response) -> bool:
        """Check if response is a soft 404 (custom error page)"""
        
        if not self.baseline_response:
            return False
        
        # Compare with baseline
        length_diff = abs(len(response.content) - self.baseline_length)
        
        # If content length is very similar to baseline, probably soft 404
        if length_diff < 500:
            return True
        
        # Check for common 404 indicators in content
        content_lower = response.text.lower()
        error_indicators = [
            'not found', '404', 'page not found', 'does not exist',
            'cannot be found', 'no longer available', 'error'
        ]
        
        for indicator in error_indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def _check_sensitive_files(self, base_url: str) -> List[Dict]:
        """Check for sensitive file exposure with soft 404 detection"""
        
        found = []
        base_url = base_url.rstrip('/')
        
        # Only check most common sensitive files
        priority_files = [
            'robots.txt', 'sitemap.xml', '.env', '.git/config',
            'wp-config.php', 'config.php', 'phpinfo.php',
            'backup.sql', 'database.sql', '.htaccess'
        ]
        
        def check_file(file_path):
            try:
                url = f"{base_url}/{file_path}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                # Only count as found if:
                # 1. Status 200
                # 2. Not a soft 404
                # 3. Has meaningful content
                if response.status_code == 200:
                    content_length = len(response.content)
                    
                    # Skip if too small (empty/error) or same as baseline
                    if content_length < 50:
                        return None
                    
                    if self._is_soft_404(response):
                        return None
                    
                    return {
                        'file': file_path,
                        'url': url,
                        'status': response.status_code,
                        'size': content_length,
                        'risk': self._get_file_risk(file_path)
                    }
            except:
                pass
            return None
        
        # Check priority files
        for file_path in priority_files:
            result = check_file(file_path)
            if result:
                found.append(result)
                risk_icon = "🔴" if result['risk'] == 'critical' else "🟠" if result['risk'] == 'high' else "🟡"
                print(f"      {risk_icon} Found: {result['file']} ({result['risk']})")
        
        return found
    
    def _get_file_risk(self, file_path: str) -> str:
        """Determine risk level of exposed file"""
        
        critical_patterns = ['.env', 'config.php', 'wp-config', '.git', 'id_rsa', 
                           'private', 'secret', 'backup.sql', 'database.sql', 'dump.sql']
        high_patterns = ['.sql', '.bak', 'phpinfo', 'debug', '.log']
        
        file_lower = file_path.lower()
        
        for pattern in critical_patterns:
            if pattern in file_lower:
                return 'critical'
        
        for pattern in high_patterns:
            if pattern in file_lower:
                return 'high'
        
        return 'medium'
    
    def _test_sqli(self, url: str) -> List[Dict]:
        """Test for SQL Injection - with better detection"""
        
        vulnerabilities = []
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            # No parameters to test
            return vulnerabilities
        
        for param_name in list(params.keys())[:3]:  # Test max 3 params
            for payload in SQLI_PAYLOADS[:3]:  # Test first 3 payloads
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                    
                    response = self.session.get(full_url, timeout=self.timeout)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'sql syntax', 'mysql_fetch', 'sqlite_', 'pg_query',
                        'ORA-', 'SQL Server', 'ODBC', 'JET Database',
                        'you have an error in your sql', 'unclosed quotation mark'
                    ]
                    
                    content_lower = response.text.lower()
                    for error in sql_errors:
                        if error.lower() in content_lower:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': error,
                                'url': full_url,
                                'risk': 'critical'
                            })
                            print(f"      🔴 SQLI found in: {param_name}")
                            break
                    
                    time.sleep(ScanConfig.REQUEST_DELAY)
                    
                except:
                    pass
        
        return vulnerabilities
    
    def _test_xss(self, url: str) -> List[Dict]:
        """Test for XSS - with better detection"""
        
        vulnerabilities = []
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        # Simple unique marker
        marker = "xss_test_12345"
        
        for param_name in list(params.keys())[:3]:
            try:
                # First test with simple marker
                test_params = params.copy()
                test_params[param_name] = [marker]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                response = self.session.get(full_url, timeout=self.timeout)
                
                # Check if marker is reflected
                if marker in response.text:
                    # Now test with actual XSS payload
                    xss_payload = f"<script>{marker}</script>"
                    test_params[param_name] = [xss_payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                    
                    response = self.session.get(full_url, timeout=self.timeout)
                    
                    if xss_payload in response.text:
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'subtype': 'Reflected XSS',
                            'parameter': param_name,
                            'payload': xss_payload,
                            'url': full_url,
                            'risk': 'high'
                        })
                        print(f"      🟠 XSS found in: {param_name}")
                
                time.sleep(ScanConfig.REQUEST_DELAY)
                
            except:
                pass
        
        return vulnerabilities
    
    def _test_open_redirect(self, url: str) -> List[Dict]:
        """Test for open redirect - FIXED VERSION"""
        
        vulnerabilities = []
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 
                          'return_url', 'redir', 'dest', 'destination', 'go']
        
        evil_url = "https://evil.com/malicious"
        
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for param in redirect_params:
            try:
                test_url = f"{base_url}/?{param}={urllib.parse.quote(evil_url)}"
                response = self.session.get(
                    test_url, 
                    timeout=self.timeout, 
                    allow_redirects=False
                )
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if location:
                        # Parse redirect location
                        loc_parsed = urllib.parse.urlparse(location)
                        
                        # ONLY flag if redirect actually goes to evil.com
                        if loc_parsed.netloc and 'evil.com' in loc_parsed.netloc.lower():
                            vulnerabilities.append({
                                'type': 'Open Redirect',
                                'parameter': param,
                                'url': test_url,
                                'redirects_to': location,
                                'risk': 'medium'
                            })
                            print(f"      🔴 CONFIRMED open redirect: {param}")
                            break  # Found one, no need to test more
                        
                        # Also check if evil URL is embedded in redirect
                        if 'evil.com' in location:
                            vulnerabilities.append({
                                'type': 'Open Redirect',
                                'parameter': param,
                                'url': test_url,
                                'redirects_to': location,
                                'risk': 'medium'
                            })
                            print(f"      🔴 CONFIRMED open redirect: {param}")
                            break
                
                time.sleep(ScanConfig.REQUEST_DELAY)
                
            except:
                pass
        
        if not vulnerabilities:
            print("      ✅ No open redirects found")
        
        return vulnerabilities
    
    def _calculate_risk_score(self, result: VulnResult) -> int:
        """Calculate overall risk score"""
        
        score = 0
        
        for vuln in result.vulnerabilities:
            if vuln.get('risk') == 'critical':
                score += 30
            elif vuln.get('risk') == 'high':
                score += 20
            elif vuln.get('risk') == 'medium':
                score += 10
            else:
                score += 5
        
        for f in result.sensitive_files:
            if f.get('risk') == 'critical':
                score += 25
            elif f.get('risk') == 'high':
                score += 15
            else:
                score += 5
        
        return min(100, score)


if __name__ == "__main__":
    print("🧪 Testing Vulnerability Scanner...")
    
    scanner = VulnerabilityScanner()
    
    # Test with different sites
    targets = [
        "https://www.google.com",
        "https://github.com"
    ]
    
    for target in targets:
        print(f"\n{'='*60}")
        print(f"Target: {target}")
        print("="*60)
        
        result = scanner.scan(target)
        
        print(f"\n📊 Results:")
        print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"   Sensitive Files: {len(result.sensitive_files)}")
        print(f"   Risk Score: {result.risk_score}/100")