"""
📁 DIRECTORY SCANNER - FIXED VERSION
Reduced false positives
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import COMMON_DIRECTORIES, ScanConfig


@dataclass
class DirResult:
    """Directory scan result"""
    base_url: str = ""
    found_directories: List[Dict] = field(default_factory=list)
    total_checked: int = 0
    interesting_findings: List[Dict] = field(default_factory=list)


class DirectoryScanner:
    """
    Directory Scanner - Fixed version with reduced false positives
    """
    
    def __init__(self, timeout: int = ScanConfig.READ_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ScanConfig.USER_AGENT
        })
        self.session.verify = False
        
        # Baseline for soft 404 detection
        self.baseline_length = 0
        self.baseline_words = set()
    
    def scan(self, url: str, wordlist: List[str] = None) -> DirResult:
        """Scan for directories with reduced false positives"""
        
        result = DirResult(base_url=url)
        
        if wordlist is None:
            wordlist = COMMON_DIRECTORIES
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        url = url.rstrip('/')
        
        print(f"\n📁 Scanning directories on: {url}")
        print(f"   Checking {len(wordlist)} paths...")
        
        # Get baseline first
        self._get_baseline(url)
        
        found = []
        
        def check_directory(directory):
            try:
                test_url = f"{url}/{directory}"
                response = self.session.get(
                    test_url, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                status = response.status_code
                
                # 200 OK - Check if real content or soft 404
                if status == 200:
                    if not self._is_soft_404(response):
                        return {
                            'path': directory,
                            'url': test_url,
                            'status': status,
                            'size': len(response.content),
                            'type': 'accessible',
                            'interesting': self._is_interesting(directory)
                        }
                
                # 403 Forbidden - Exists but protected
                elif status == 403:
                    return {
                        'path': directory,
                        'url': test_url,
                        'status': status,
                        'type': 'forbidden',
                        'interesting': self._is_interesting(directory)
                    }
                
                # 301/302 - Check if redirect to same path
                elif status in [301, 302]:
                    location = response.headers.get('Location', '')
                    
                    # Only count if redirect is to same directory (with trailing slash)
                    if location:
                        # Check if redirect adds trailing slash (normal behavior)
                        if location.rstrip('/').endswith('/' + directory) or \
                           location.rstrip('/') == test_url or \
                           location == test_url + '/':
                            return {
                                'path': directory,
                                'url': test_url,
                                'status': status,
                                'type': 'redirect',
                                'redirect_to': location,
                                'interesting': self._is_interesting(directory)
                            }
                        
                        # If redirects to login/home, it's a false positive
                        skip_redirects = ['login', 'signin', 'auth', '/?', '/home', '/#']
                        if any(skip in location.lower() for skip in skip_redirects):
                            return None
                
                return None
                
            except:
                return None
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_directory, d): d for d in wordlist}
            
            for future in as_completed(futures):
                result.total_checked += 1
                finding = future.result()
                
                if finding:
                    found.append(finding)
                    status_icon = self._get_status_icon(finding['status'])
                    print(f"   {status_icon} /{finding['path']} [{finding['status']}]")
        
        result.found_directories = found
        result.interesting_findings = [f for f in found if f.get('interesting')]
        
        if not found:
            print("   ✅ No exposed directories found")
        
        return result
    
    def _get_baseline(self, url: str):
        """Get baseline response for soft 404 detection"""
        try:
            random_url = f"{url}/definitely_nonexistent_path_xyz123"
            response = self.session.get(random_url, timeout=self.timeout)
            self.baseline_length = len(response.content)
            
            # Get some common words from baseline
            words = response.text.lower().split()
            self.baseline_words = set(words[:100])  # First 100 words
        except:
            self.baseline_length = 0
    
    def _is_soft_404(self, response) -> bool:
        """Check if response is a soft 404"""
        
        content_length = len(response.content)
        
        # If very similar length to baseline, probably soft 404
        if self.baseline_length > 0:
            length_diff = abs(content_length - self.baseline_length)
            if length_diff < 200:  # Very similar
                return True
        
        # Check for error indicators
        content_lower = response.text.lower()
        error_indicators = [
            'not found', '404', 'does not exist', 'page not found',
            'cannot find', 'no longer available', 'nothing here'
        ]
        
        for indicator in error_indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def _is_interesting(self, path: str) -> bool:
        """Check if path is interesting"""
        
        interesting_patterns = [
            'admin', 'backup', 'config', 'database', 'db', 
            'debug', 'log', 'private', 'secret', 'test',
            '.git', '.env', 'phpmyadmin', 'wp-admin', 'api'
        ]
        
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in interesting_patterns)
    
    def _get_status_icon(self, status: int) -> str:
        """Get icon based on status"""
        if status == 200:
            return "🟢"
        elif status == 403:
            return "🔒"
        elif status in [301, 302]:
            return "🔀"
        return "⚪"


if __name__ == "__main__":
    print("🧪 Testing Directory Scanner...")
    
    scanner = DirectoryScanner()
    
    result = scanner.scan("https://github.com")
    
    print(f"\n📊 Results:")
    print(f"   Checked: {result.total_checked}")
    print(f"   Found: {len(result.found_directories)}")
    print(f"   Interesting: {len(result.interesting_findings)}")