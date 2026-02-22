"""
🔌 PORT SCANNER
Scans for open ports and identifies services
"""

import socket
import concurrent.futures
from typing import Dict, List, Tuple
from dataclasses import dataclass
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import COMMON_PORTS, ScanConfig


@dataclass
class PortResult:
    """Result of port scan"""
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    risk: str = "unknown"
    description: str = ""


class PortScanner:
    """
    Port Scanner - Detects open ports and services
    """
    
    def __init__(self, timeout: float = ScanConfig.PORT_TIMEOUT):
        self.timeout = timeout
        self.results: List[PortResult] = []
    
    def scan_port(self, host: str, port: int) -> PortResult:
        """
        Scan a single port
        
        Args:
            host: Target hostname or IP
            port: Port number to scan
        
        Returns:
            PortResult with scan results
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Port is open
                banner = self._grab_banner(sock, port)
                
                # Get port info from config
                port_info = COMMON_PORTS.get(port, {
                    "name": "Unknown",
                    "risk": "unknown",
                    "description": "Unknown service"
                })
                
                return PortResult(
                    port=port,
                    is_open=True,
                    service=port_info["name"],
                    banner=banner,
                    risk=port_info["risk"],
                    description=port_info["description"]
                )
            else:
                return PortResult(port=port, is_open=False)
                
        except socket.timeout:
            return PortResult(port=port, is_open=False)
        except socket.error:
            return PortResult(port=port, is_open=False)
        finally:
            sock.close()
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Attempt to grab service banner
        """
        try:
            # Send probe based on port
            if port in [80, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except:
            return ""
    
    def scan_common_ports(self, host: str, ports: List[int] = None) -> List[PortResult]:
        """
        Scan common ports using threading
        
        Args:
            host: Target hostname or IP
            ports: List of ports to scan (default: COMMON_PORTS)
        
        Returns:
            List of PortResult for open ports
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        self.results = []
        open_ports = []
        
        print(f"\n🔌 Scanning {len(ports)} ports on {host}...")
        
        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=ScanConfig.MAX_THREADS) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                self.results.append(result)
                
                if result.is_open:
                    open_ports.append(result)
                    risk_icon = self._get_risk_icon(result.risk)
                    print(f"   {risk_icon} Port {result.port}: {result.service} ({result.risk})")
        
        # Sort by port number
        open_ports.sort(key=lambda x: x.port)
        
        return open_ports
    
    def scan_port_range(self, host: str, start_port: int, end_port: int) -> List[PortResult]:
        """
        Scan a range of ports
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_common_ports(host, ports)
    
    def _get_risk_icon(self, risk: str) -> str:
        """Get icon based on risk level"""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "unknown": "⚪"
        }
        return icons.get(risk, "⚪")
    
    def get_summary(self) -> Dict:
        """
        Get scan summary
        """
        open_ports = [r for r in self.results if r.is_open]
        
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for port in open_ports:
            if port.risk in risk_counts:
                risk_counts[port.risk] += 1
        
        return {
            "total_scanned": len(self.results),
            "open_ports": len(open_ports),
            "risk_breakdown": risk_counts,
            "critical_findings": [p for p in open_ports if p.risk == "critical"],
            "high_findings": [p for p in open_ports if p.risk == "high"]
        }


def resolve_hostname(hostname: str) -> str:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


if __name__ == "__main__":
    # Test the scanner
    print("🧪 Testing Port Scanner...")
    
    target = "scanme.nmap.org"  # Legal target for testing
    print(f"\n🎯 Target: {target}")
    
    # Resolve hostname
    ip = resolve_hostname(target)
    if ip:
        print(f"   IP: {ip}")
    
    # Scan
    scanner = PortScanner()
    open_ports = scanner.scan_common_ports(target)
    
    # Summary
    summary = scanner.get_summary()
    print(f"\n📊 Summary:")
    print(f"   Scanned: {summary['total_scanned']} ports")
    print(f"   Open: {summary['open_ports']} ports")
    print(f"   Critical: {summary['risk_breakdown']['critical']}")
    print(f"   High: {summary['risk_breakdown']['high']}")