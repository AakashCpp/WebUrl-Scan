"""
🌐 CYBERSENTINEL X - WEB VULNERABILITY SCANNER API
FastAPI – Production Ready (High Performance)
"""

import os
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# -----------------------
# Path setup
# -----------------------
# Resolve ensures it works on Windows and Linux (Render)
ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

# -----------------------
# Internal imports
# -----------------------
try:
    from main_scanner import WebScanner
except ImportError:
    print("❌ Error: main_scanner.py not found in the directory.")
    sys.exit(1)

# -----------------------
# App init
# -----------------------
app = FastAPI(
    title="CyberSentinel X - Web Security Engine",
    description="API for SSL, Ports, Headers, and Tech Vulnerability Scanning",
    version="1.2.0"
)

# Enable CORS for React Frontend Integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Load Scanner ONCE
# -----------------------
web_scanner = WebScanner()

# -----------------------
# Request Models
# -----------------------
class ScanRequest(BaseModel):
    target: str = Field(..., example="google.com")
    full_scan: bool = True

# -----------------------
# 1️⃣ Health Check
# -----------------------
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "engine": "WebScanner Active",
        "ml_engine": "Disabled (Cloud mode recommended)"
    }

# =====================================================
# 2️⃣ WEB VULNERABILITY SCAN
# =====================================================
@app.post("/api/scan")
async def scan_website(request: ScanRequest):
    """
    Performs a comprehensive security scan:
    - SSL Certificate Validation
    - Port Scanning (Nmap)
    - Security Headers Check
    - Tech Stack Detection
    """

    target_input = request.target.strip()
    
    if not target_input:
        raise HTTPException(status_code=400, detail="Target URL/Domain is required")

    try:
        # Performing the scan using main_scanner logic
        report = (
            web_scanner.scan(target_input, full_scan=True)
            if request.full_scan
            else web_scanner.quick_scan(target_input)
        )

        return {
            "status": "success",
            "data": {
                "target": report.target,
                "ip_address": report.ip_address,
                "scan_time": report.scan_time,
                "duration": f"{report.duration}s",
                "grade": report.grade,
                "risk_score": report.risk_score,
                "total_vulnerabilities": report.total_vulnerabilities,
                "results": {
                    "ports": report.port_results,
                    "ssl": report.ssl_results,
                    "headers": report.header_results,
                    "technologies": report.tech_results,
                    "vulnerabilities": report.vuln_results,
                    "directories": report.dir_results
                }
            }
        }

    except Exception as e:
        # Catching any internal scanner errors
        print(f"DEBUG ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# -----------------------
# Local run / Render Entry point
# -----------------------
if __name__ == "__main__":
    # Get port from environment for Cloud Deployment
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api_server:app", host="0.0.0.0", port=port, reload=True)