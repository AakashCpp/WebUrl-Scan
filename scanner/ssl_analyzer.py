"""
🔐 SSL/TLS ANALYZER
Analyzes SSL certificates and configuration
"""

import ssl
import socket
import OpenSSL
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ScanConfig


@dataclass
class SSLResult:
    """SSL analysis result"""
    has_ssl: bool = False
    is_valid: bool = False
    issuer: str = ""
    subject: str = ""
    version: str = ""
    expires: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    cipher_suite: str = ""
    key_size: int = 0
    vulnerabilities: List[str] = None
    grade: str = "F"
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class SSLAnalyzer:
    """
    SSL/TLS Analyzer - Checks certificate and configuration
    """
    
    def __init__(self, timeout: int = ScanConfig.CONNECT_TIMEOUT):
        self.timeout = timeout
    
    def analyze(self, hostname: str, port: int = 443) -> SSLResult:
        """
        Analyze SSL/TLS configuration
        
        Args:
            hostname: Target hostname
            port: Port number (default: 443)
        
        Returns:
            SSLResult with analysis
        """
        result = SSLResult()
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We'll verify manually
            
            # Connect
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result.has_ssl = True
                    
                    # Get certificate
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, 
                        cert_bin
                    )
                    
                    # Parse certificate
                    result = self._parse_certificate(cert, ssock, hostname)
                    
        except ssl.SSLError as e:
            result.vulnerabilities.append(f"SSL Error: {str(e)}")
        except socket.timeout:
            result.vulnerabilities.append("Connection timeout")
        except socket.error as e:
            result.vulnerabilities.append(f"Connection error: {str(e)}")
        except Exception as e:
            result.vulnerabilities.append(f"Error: {str(e)}")
        
        return result
    
    def _parse_certificate(self, cert, ssock, hostname: str) -> SSLResult:
        """Parse certificate details"""
        
        result = SSLResult(has_ssl=True)
        
        # Issuer
        issuer = cert.get_issuer()
        result.issuer = f"{issuer.CN}" if issuer.CN else str(issuer)
        
        # Subject
        subject = cert.get_subject()
        result.subject = f"{subject.CN}" if subject.CN else str(subject)
        
        # Expiry
        not_after = cert.get_notAfter().decode('utf-8')
        expiry_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        result.expires = expiry_date.strftime('%Y-%m-%d')
        result.days_until_expiry = (expiry_date - datetime.now()).days
        result.is_expired = result.days_until_expiry < 0
        
        # Check if expiring soon
        if result.days_until_expiry < 30 and not result.is_expired:
            result.vulnerabilities.append(f"Certificate expires in {result.days_until_expiry} days")
        elif result.is_expired:
            result.vulnerabilities.append("Certificate has EXPIRED!")
        
        # SSL Version
        result.version = ssock.version()
        
        # Check for weak versions
        weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        if result.version in weak_versions:
            result.vulnerabilities.append(f"Weak SSL version: {result.version}")
        
        # Cipher suite
        cipher = ssock.cipher()
        if cipher:
            result.cipher_suite = cipher[0]
            result.key_size = cipher[2]
            
            # Check for weak ciphers
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
            for weak in weak_ciphers:
                if weak in result.cipher_suite.upper():
                    result.vulnerabilities.append(f"Weak cipher: {result.cipher_suite}")
                    break
            
            # Check key size
            if result.key_size < 128:
                result.vulnerabilities.append(f"Weak key size: {result.key_size} bits")
        
        # Verify certificate
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result.is_valid = True
        except ssl.CertificateError:
            result.vulnerabilities.append("Certificate validation failed")
            result.is_valid = False
        except:
            pass
        
        # Calculate grade
        result.grade = self._calculate_grade(result)
        
        return result
    
    def _calculate_grade(self, result: SSLResult) -> str:
        """Calculate SSL grade"""
        
        if not result.has_ssl:
            return "F"
        
        score = 100
        
        # Deductions
        if result.is_expired:
            score -= 50
        elif result.days_until_expiry < 30:
            score -= 10
        
        if not result.is_valid:
            score -= 30
        
        if result.version in ['SSLv2', 'SSLv3']:
            score -= 40
        elif result.version in ['TLSv1', 'TLSv1.1']:
            score -= 20
        
        if result.key_size < 128:
            score -= 30
        elif result.key_size < 256:
            score -= 10
        
        # Each vulnerability
        score -= len(result.vulnerabilities) * 5
        
        # Convert to grade
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def check_vulnerabilities(self, hostname: str, port: int = 443) -> List[str]:
        """
        Check for known SSL vulnerabilities
        """
        vulnerabilities = []
        
        # Check for SSLv2 support
        if self._test_ssl_version(hostname, port, ssl.PROTOCOL_SSLv23):
            pass  # Just testing connectivity
        
        # Additional checks could include:
        # - POODLE (SSLv3)
        # - BEAST
        # - CRIME
        # - Heartbleed
        # - FREAK
        # - Logjam
        
        return vulnerabilities
    
    def _test_ssl_version(self, hostname: str, port: int, version) -> bool:
        """Test if specific SSL version is supported"""
        try:
            context = ssl.SSLContext(version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
        except:
            return False


if __name__ == "__main__":
    print("🧪 Testing SSL Analyzer...")
    
    targets = ["google.com", "github.com", "expired.badssl.com"]
    
    analyzer = SSLAnalyzer()
    
    for target in targets:
        print(f"\n🔐 Analyzing: {target}")
        result = analyzer.analyze(target)
        
        print(f"   Has SSL: {result.has_ssl}")
        print(f"   Valid: {result.is_valid}")
        print(f"   Grade: {result.grade}")
        print(f"   Version: {result.version}")
        print(f"   Expires: {result.expires} ({result.days_until_expiry} days)")
        print(f"   Issuer: {result.issuer}")
        
        if result.vulnerabilities:
            print(f"   ⚠️ Vulnerabilities:")
            for vuln in result.vulnerabilities:
                print(f"      - {vuln}")