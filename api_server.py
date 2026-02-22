"""
🌐 BERT URL PHISHING DETECTION API
FastAPI – ML Dedicated Version
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
ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

# -----------------------
# Internal imports
# -----------------------
try:
    from ml import BertURLDetector
except ImportError as e:
    print(f"❌ Error: ML module not found. Check your 'ml' folder. {e}")
    sys.exit(1)

# -----------------------
# App init
# -----------------------
app = FastAPI(
    title="CyberSentinel X - ML Phishing Detector",
    description="Fine-tuned BERT model for real-time Phishing URL detection",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Load ML Model ONCE
# -----------------------
# Isme time lagega kyunki ye model download/load karega
bert_detector = BertURLDetector()

# -----------------------
# Request Models
# -----------------------
class URLCheckRequest(BaseModel):
    url: str = Field(..., example="http://secure-login-bank.com")

# -----------------------
# Health Check
# -----------------------
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "service": "BERT URL Detector",
        "model_status": "loaded"
    }

# =====================================================
# 1️⃣ BERT URL PHISHING DETECTION
# =====================================================
@app.post("/api/url-scan")
async def check_url(request: URLCheckRequest):
    """
    ML-based URL detection:
    - Input: raw URL string
    - Processing: BERT Tokenization & Classification
    - Output: phishing / legitimate with confidence score
    """
    
    clean_url = request.url.strip()
    
    if not clean_url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        # Prediction logic from your ml/bert_url_detector.py
        prediction = bert_detector.predict(clean_url)

        return {
            "status": "success",
            "url": clean_url,
            "analysis": {
                "prediction": prediction["label"],
                "confidence": round(float(prediction["confidence"]), 4),
                "engine": "BERT-Base-Uncased"
            }
        }

    except Exception as e:
        print(f"DEBUG ML ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")

# -----------------------
# Deployment Execution
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api_server:app", host="0.0.0.0", port=port, reload=False) # Reload False for ML stability