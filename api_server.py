"""
🌐 WEB VULNERABILITY SCANNER + BERT URL DETECTION API
FastAPI – Production Ready
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import sys

# -----------------------
# Path setup
# -----------------------
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

# -----------------------
# Internal imports
# -----------------------
from main_scanner import WebScanner
from ml import BertURLDetector

# -----------------------
# App init
# -----------------------
app = FastAPI(
    title="Web Scan + ML Security API",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Load scanners ONCE
# -----------------------
web_scanner = WebScanner()
bert_detector = BertURLDetector()

# -----------------------
# Request Models
# -----------------------
class ScanRequest(BaseModel):
    target: str
    full_scan: bool = True


class URLCheckRequest(BaseModel):
    url: str


# -----------------------
# Health
# -----------------------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "services": {
            "web_scanner": "active",
            "bert_url_detector": "active"
        }
    }


# =====================================================
# 1️⃣ WEB VULNERABILITY SCAN (BLOCKING)
# =====================================================
@app.post("/api/scan")
def scan_website(request: ScanRequest):
    """
    Blocking scan:
    - frontend waits
    - full scan completes
    - returns final JSON only
    """

    if not request.target.strip():
        raise HTTPException(status_code=400, detail="Target URL required")

    try:
        report = (
            web_scanner.scan(request.target, full_scan=True)
            if request.full_scan
            else web_scanner.quick_scan(request.target)
        )

        return {
            "target": report.target,
            "ip_address": report.ip_address,
            "scan_time": report.scan_time,
            "duration": report.duration,
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

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


# =====================================================
# 2️⃣ BERT URL PHISHING DETECTION
# =====================================================
@app.post("/api/url-scan")
def check_url(request: URLCheckRequest):
    """
    ML-based URL detection
    - uses fine-tuned BERT
    - returns phishing / legitimate
    """

    if not request.url.strip():
        raise HTTPException(status_code=400, detail="URL required")

    try:
        prediction = bert_detector.predict(request.url)

        return {
            "url": request.url,
            "prediction": prediction["label"],
            "confidence": prediction["confidence"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")


# -----------------------
# Local run (DEV only)
# -----------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
