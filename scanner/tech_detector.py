"""
🔍 TECHNOLOGY DETECTOR
Detects technologies, CMS, frameworks used by website
"""

import requests
import re
from dataclasses import dataclass, field
from typing import Dict, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import TECH_SIGNATURES, ScanConfig


@dataclass
class TechResult:
    """Technology detection result"""
    url: str = ""
    technologies: List[Dict] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    cms: str = ""
    framework: str = ""
    javascript_libraries: List[str] = field(default_factory=list)


class TechnologyDetector:
    """
    Technology Detector - Identifies web technologies
    """
    
    def __init__(self, timeout: int = ScanConfig.READ_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ScanConfig.USER_AGENT
        })
        self.session.verify = False
    
    def detect(self, url: str) -> TechResult:
        """
        Detect technologies used by website
        
        Args:
            url: Target URL
        
        Returns:
            TechResult with detected technologies
        """
        result = TechResult(url=url)
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        print(f"\n🔍 Detecting technologies: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check headers
            self._analyze_headers(response, result)
            
            # Check HTML content
            self._analyze_html(response, result)
            
            # Check cookies
            self._analyze_cookies(response, result)
            
            # Check for known CMS/frameworks
            self._detect_cms(url, response, result)
            
            # Detect JavaScript libraries
            self._detect_js_libraries(response, result)
            
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
        
        return result
    
    def _analyze_headers(self, response, result: TechResult):
        """Analyze response headers"""
        
        headers = response.headers
        
        # Server
        if 'Server' in headers:
            result.server = headers['Server']
            result.technologies.append({
                'name': headers['Server'],
                'category': 'Web Server',
                'source': 'Header'
            })
            print(f"   🖥️  Server: {result.server}")
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            result.powered_by = headers['X-Powered-By']
            result.technologies.append({
                'name': headers['X-Powered-By'],
                'category': 'Runtime',
                'source': 'Header'
            })
            print(f"   ⚡ Powered by: {result.powered_by}")
        
        # X-Generator
        if 'X-Generator' in headers:
            result.technologies.append({
                'name': headers['X-Generator'],
                'category': 'CMS/Generator',
                'source': 'Header'
            })
    
    def _analyze_html(self, response, result: TechResult):
        """Analyze HTML content"""
        
        html = response.text
        
        # Meta generator tag
        generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if generator_match:
            generator = generator_match.group(1)
            result.technologies.append({
                'name': generator,
                'category': 'CMS/Generator',
                'source': 'Meta tag'
            })
            result.cms = generator
            print(f"   📝 CMS: {generator}")
        
        # Check for common patterns
        patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
            'Joomla': [r'Joomla', r'/components/com_'],
            'Drupal': [r'Drupal', r'/sites/default/'],
            'Magento': [r'Magento', r'/skin/frontend/', r'Mage.Cookies'],
            'Shopify': [r'Shopify', r'cdn.shopify.com'],
            'Wix': [r'wix.com', r'wixsite.com'],
            'Squarespace': [r'squarespace.com', r'static.squarespace.com'],
            'React': [r'react', r'_reactRootContainer', r'__REACT'],
            'Angular': [r'ng-version', r'ng-app', r'angular'],
            'Vue.js': [r'Vue', r'__VUE__', r'v-cloak'],
            'jQuery': [r'jquery', r'jQuery'],
            'Bootstrap': [r'bootstrap', r'Bootstrap'],
        }
        
        for tech, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, html, re.I):
                    if not any(t['name'] == tech for t in result.technologies):
                        result.technologies.append({
                            'name': tech,
                            'category': self._get_category(tech),
                            'source': 'HTML pattern'
                        })
                        print(f"   🔧 Detected: {tech}")
                    break
    
    def _analyze_cookies(self, response, result: TechResult):
        """Analyze cookies"""
        
        cookies = response.cookies
        
        cookie_signatures = {
            'laravel_session': 'Laravel',
            'XSRF-TOKEN': 'Laravel/Vue',
            'csrftoken': 'Django',
            'sessionid': 'Django',
            'PHPSESSID': 'PHP',
            'JSESSIONID': 'Java',
            'ASP.NET_SessionId': 'ASP.NET',
            'wordpress_logged_in': 'WordPress',
            'wp-settings': 'WordPress',
        }
        
        for cookie in cookies:
            for sig, tech in cookie_signatures.items():
                if sig in cookie.name:
                    if not any(t['name'] == tech for t in result.technologies):
                        result.technologies.append({
                            'name': tech,
                            'category': 'Framework',
                            'source': 'Cookie'
                        })
                        print(f"   🍪 Detected via cookie: {tech}")
    
    def _detect_cms(self, url: str, response, result: TechResult):
        """Detect CMS by checking specific paths"""
        
        cms_paths = {
            'WordPress': ['/wp-login.php', '/wp-admin/', '/xmlrpc.php'],
            'Joomla': ['/administrator/', '/configuration.php'],
            'Drupal': ['/user/login', '/core/misc/drupal.js'],
            'Magento': ['/admin/', '/downloader/'],
        }
        
        for cms, paths in cms_paths.items():
            for path in paths:
                try:
                    test_url = url.rstrip('/') + path
                    resp = self.session.get(test_url, timeout=3, allow_redirects=False)
                    
                    if resp.status_code in [200, 302, 403]:
                        if not result.cms:
                            result.cms = cms
                        if not any(t['name'] == cms for t in result.technologies):
                            result.technologies.append({
                                'name': cms,
                                'category': 'CMS',
                                'source': f'Path: {path}'
                            })
                            print(f"   📦 CMS confirmed: {cms}")
                        break
                except:
                    pass
    
    def _detect_js_libraries(self, response, result: TechResult):
        """Detect JavaScript libraries"""
        
        html = response.text
        
        js_patterns = {
            'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)', r'jquery\.min\.js'],
            'React': [r'react[.-](\d+\.\d+\.\d+)', r'react\.production\.min\.js'],
            'Vue.js': [r'vue[.-](\d+\.\d+\.\d+)', r'vue\.min\.js'],
            'Angular': [r'angular[.-](\d+\.\d+\.\d+)'],
            'Bootstrap': [r'bootstrap[.-](\d+\.\d+\.\d+)'],
            'Lodash': [r'lodash[.-](\d+\.\d+\.\d+)'],
            'Moment.js': [r'moment[.-](\d+\.\d+\.\d+)'],
            'axios': [r'axios[.-](\d+\.\d+\.\d+)'],
        }
        
        for lib, patterns in js_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, html, re.I)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    lib_name = f"{lib} {version}" if version else lib
                    if lib_name not in result.javascript_libraries:
                        result.javascript_libraries.append(lib_name)
    
    def _get_category(self, tech: str) -> str:
        """Get category for technology"""
        
        categories = {
            'WordPress': 'CMS',
            'Joomla': 'CMS',
            'Drupal': 'CMS',
            'Magento': 'E-commerce',
            'Shopify': 'E-commerce',
            'React': 'JavaScript Framework',
            'Angular': 'JavaScript Framework',
            'Vue.js': 'JavaScript Framework',
            'jQuery': 'JavaScript Library',
            'Bootstrap': 'CSS Framework',
        }
        
        return categories.get(tech, 'Other')


if __name__ == "__main__":
    print("🧪 Testing Technology Detector...")
    
    targets = ["github.com", "wordpress.com", "shopify.com"]
    
    detector = TechnologyDetector()
    
    for target in targets:
        result = detector.detect(target)
        
        print(f"\n📊 Results for {target}:")
        print(f"   Server: {result.server}")
        print(f"   CMS: {result.cms or 'Not detected'}")
        print(f"   Technologies: {len(result.technologies)}")
        
        for tech in result.technologies:
            print(f"      - {tech['name']} ({tech['category']})")