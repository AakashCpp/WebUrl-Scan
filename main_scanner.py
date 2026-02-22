"""
🔒 WEB VULNERABILITY SCANNER - MAIN SCRIPT
API & CLI compatible (NO report saving)
"""

import sys
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict
import warnings
warnings.filterwarnings("ignore")

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

from scanner.port_scanner import PortScanner, resolve_hostname
from scanner.ssl_analyzer import SSLAnalyzer
from scanner.header_analyzer import HeaderAnalyzer
from scanner.vuln_scanner import VulnerabilityScanner
from scanner.dir_scanner import DirectoryScanner
from scanner.tech_detector import TechnologyDetector


# =========================
# DATA MODEL
# =========================
@dataclass
class ScanReport:
    target: str
    ip_address: str = ""
    scan_time: str = ""
    duration: float = 0.0

    port_results: Dict = field(default_factory=dict)
    ssl_results: Dict = field(default_factory=dict)
    header_results: Dict = field(default_factory=dict)
    vuln_results: Dict = field(default_factory=dict)
    dir_results: Dict = field(default_factory=dict)
    tech_results: Dict = field(default_factory=dict)

    total_vulnerabilities: int = 0
    risk_score: int = 0
    grade: str = "F"


# =========================
# MAIN SCANNER
# =========================
class WebScanner:
    def __init__(self):
        self.port_scanner = PortScanner()
        self.ssl_analyzer = SSLAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.vuln_scanner = VulnerabilityScanner()
        self.dir_scanner = DirectoryScanner()
        self.tech_detector = TechnologyDetector()

    def scan(self, target: str, full_scan: bool = True) -> ScanReport:
        start_time = time.time()

        target = target.strip().lower()
        hostname = (
            target.split("//")[1].split("/")[0]
            if target.startswith(("http://", "https://"))
            else target.split("/")[0]
        )

        report = ScanReport(
            target=target,
            scan_time=datetime.now().isoformat()
        )

        # Resolve IP
        ip = resolve_hostname(hostname)
        report.ip_address = ip or ""

        # ================= PORT SCAN =================
        if ip:
            try:
                open_ports = self.port_scanner.scan_common_ports(ip)
                report.port_results = {
                    "open_ports": [
                        {
                            "port": p.port,
                            "service": p.service,
                            "risk": p.risk,
                            "banner": p.banner,
                        }
                        for p in open_ports
                    ],
                    "summary": self.port_scanner.get_summary(),
                }
            except Exception as e:
                report.port_results = {"error": str(e)}

        # ================= SSL =================
        try:
            ssl = self.ssl_analyzer.analyze(hostname)
            report.ssl_results = {
                "has_ssl": ssl.has_ssl,
                "is_valid": ssl.is_valid,
                "grade": ssl.grade,
                "version": ssl.version,
                "issuer": ssl.issuer,
                "expires": ssl.expires,
                "days_until_expiry": ssl.days_until_expiry,
                "vulnerabilities": ssl.vulnerabilities,
            }
        except Exception as e:
            report.ssl_results = {"error": str(e), "has_ssl": False}

        # ================= HEADERS =================
        try:
            url = f"https://{hostname}" if report.ssl_results.get("has_ssl") else f"http://{hostname}"
            headers = self.header_analyzer.analyze(url)
            report.header_results = {
                "score": headers.final_score,
                "grade": headers.grade,
                "summary": headers.summary,
                "missing_headers": headers.missing_headers,
                "present_headers": headers.present_headers,
                "partial_headers": headers.partial_headers,
                "information_disclosure": headers.info_disclosure,
                "other_issues": headers.other_issues,
            }
        except Exception as e:
            report.header_results = {"error": str(e)}

        # ================= TECH =================
        try:
            tech = self.tech_detector.detect(url)
            report.tech_results = {
                "server": tech.server,
                "cms": tech.cms,
                "technologies": tech.technologies,
                "javascript_libraries": tech.javascript_libraries,
            }
        except Exception as e:
            report.tech_results = {"error": str(e)}

        # ================= FULL SCAN =================
        if full_scan:
            try:
                vuln = self.vuln_scanner.scan(url)
                report.vuln_results = {
                    "vulnerabilities": vuln.vulnerabilities,
                    "sensitive_files": vuln.sensitive_files,
                    "risk_score": vuln.risk_score,
                }
            except Exception as e:
                report.vuln_results = {"error": str(e)}

            try:
                dirs = self.dir_scanner.scan(url)
                report.dir_results = {
                    "found_directories": dirs.found_directories,
                    "interesting_findings": dirs.interesting_findings,
                    "total_checked": dirs.total_checked,
                }
            except Exception as e:
                report.dir_results = {"error": str(e)}

        # ================= SCORE =================
        report.duration = round(time.time() - start_time, 2)
        self._calculate_final_score(report)

        return report

    def quick_scan(self, target: str) -> ScanReport:
        return self.scan(target, full_scan=False)

    def _calculate_final_score(self, report: ScanReport):
        score = 0
        count = 0

        if report.port_results.get("summary"):
            rb = report.port_results["summary"].get("risk_breakdown", {})
            score += rb.get("critical", 0) * 20
            score += rb.get("high", 0) * 10
            count += report.port_results["summary"].get("open_ports", 0)

        if report.ssl_results and not report.ssl_results.get("has_ssl", True):
            score += 30
            count += 1

        if report.vuln_results.get("vulnerabilities"):
            for v in report.vuln_results["vulnerabilities"]:
                score += 25 if v.get("risk") == "critical" else 10
                count += 1

        report.risk_score = min(score, 100)
        report.total_vulnerabilities = count

        report.grade = (
            "A+" if score <= 10 else
            "A" if score <= 20 else
            "B" if score <= 35 else
            "C" if score <= 50 else
            "D" if score <= 70 else
            "F"
        )


# =========================
# CLI SUPPORT
# =========================
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target: ")
    quick = "--quick" in sys.argv or "-q" in sys.argv

    scanner = WebScanner()
    result = scanner.quick_scan(target) if quick else scanner.scan(target)
    print("\n✅ Scan complete")
