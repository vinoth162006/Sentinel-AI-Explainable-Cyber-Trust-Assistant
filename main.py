import logging
import urllib.parse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Import modular security engines
from ml_classifier import classifier
from utils.ssl_checker import check_ssl_certificate
from utils.whois_checker import check_domain_age
from utils.content_analyzer import analyze_web_content

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentinelBackend")

app = FastAPI(
    title="Sentinel AI - Cyber Trust Assistant API",
    description="Backend analysis engine for URL heuristics, ML phishing detection, SSL validation, and WHOIS domain age.",
    version="1.0.0"
)

# Enable CORS for Chrome Extension requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str
    dom_telemetry: Optional[Dict[str, Any]] = None

class FactorDetail(BaseModel):
    status: str  # "safe", "warning", "danger"
    name: str
    desc: str

class AnalysisResult(BaseModel):
    url: str
    domain: str
    trust_score: int
    risk_level: str
    factors: List[FactorDetail]
    details: Optional[Dict[str, Any]] = None

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_url(request: AnalyzeRequest):
    url_str = request.url.strip()
    if not url_str:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    logger.info(f"Received Deep Analysis Request for URL: {url_str}")
    
    try:
        parsed = urllib.parse.urlparse(url_str)
        domain = parsed.hostname or parsed.path.split('/')[0]
        scheme = parsed.scheme
        
        # 1. Base Score & Factors
        score = 100
        factors = []
        
        # Heuristics: HTTP vs HTTPS
        if scheme == "https":
            factors.append({
                "status": "safe",
                "name": "Secure Protocol (HTTPS)",
                "desc": "The site uses HTTPS encryption to protect data in transit."
            })
        else:
            score -= 30
            factors.append({
                "status": "danger",
                "name": "Insecure Protocol (HTTP)",
                "desc": "The site uses unencrypted HTTP. Intercepted data is vulnerable to sniffing."
            })
            
        # Heuristics: IP hostname
        import re
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ip_pattern, domain):
            score -= 20
            factors.append({
                "status": "danger",
                "name": "Raw IP Address Host",
                "desc": "Direct IP hosting detected. Legitimate sites map to registered domain text."
            })
            
        # Heuristics: Special characters
        if "@" in url_str:
            score -= 15
            factors.append({
                "status": "danger",
                "name": "Redirection Symbol (@)",
                "desc": "Contains '@', forcing the browser to drop credentials and redirect to the trailing host."
            })

        # 2. Machine Learning Phishing Prediction (Phase 3)
        ml_label, ml_confidence, features = classifier.predict(url_str)
        if ml_label == "Phishing":
            score -= 40
            factors.append({
                "status": "danger",
                "name": "ML Phishing Indicator",
                "desc": f"AI model classified this URL structure as phishing (Confidence: {ml_confidence:.1%})."
            })
        elif ml_label == "Suspicious":
            score -= 20
            factors.append({
                "status": "warning",
                "name": "ML Suspicious Score",
                "desc": f"AI patterns indicate structural similarities to scam setups (Confidence: {ml_confidence:.1%})."
            })
        else:
            # Safe ML prediction
            factors.append({
                "status": "safe",
                "name": "ML Safe URL Verification",
                "desc": f"AI model indicates URL structural patterns resemble benign destinations."
            })
            
        # 3. SSL Certificate Validation (Phase 5)
        ssl_info = {"valid": False, "issuer": "Unknown", "days_to_expiry": -1}
        if scheme == "https":
            ssl_info = check_ssl_certificate(domain)
            if ssl_info["valid"]:
                factors.append({
                    "status": "safe",
                    "name": "Verified SSL Certificate",
                    "desc": f"SSL certificate is valid. Issued by: {ssl_info['issuer']}. Expires in {ssl_info['days_to_expiry']} days."
                })
            else:
                score -= 25
                error_msg = ssl_info.get("error") or "Untrusted or mismatch certificate."
                factors.append({
                    "status": "danger",
                    "name": "Invalid SSL Certificate",
                    "desc": f"SSL check failed: {error_msg} Avoid submitting credentials."
                })
        else:
            ssl_info["error"] = "HTTPS is not enabled"
            
        # 4. WHOIS Domain Age Analysis (Phase 5)
        whois_info = {"age_days": -1, "registrar": "Unknown", "is_young": False}
        if not re.match(ip_pattern, domain) and domain != "localhost":
            whois_info = check_domain_age(domain)
            if whois_info["age_days"] != -1:
                if whois_info["is_young"]:
                    score -= 20
                    factors.append({
                        "status": "warning",
                        "name": "Newly Registered Domain",
                        "desc": f"Domain was registered recently ({whois_info['age_days']} days ago). New domains are frequently used in cyber scams."
                    })
                else:
                    factors.append({
                        "status": "safe",
                        "name": "Established Domain Age",
                        "desc": f"Domain history is established ({whois_info['age_days']} days old). Registered via {whois_info['registrar']}."
                    })
            else:
                # WHOIS record missing/error
                factors.append({
                    "status": "warning",
                    "name": "Undocumented WHOIS Record",
                    "desc": "Registry data was not found or timed out. Domain reputation could not be fully verified."
                })
                
        # 5. DOM / Page Content Analysis (Phase 5)
        if request.dom_telemetry:
            dom_factors = analyze_web_content(domain, request.dom_telemetry)
            for df in dom_factors:
                factors.append(df)
                if df["status"] == "danger":
                    score -= 30
                elif df["status"] == "warning":
                    score -= 10

        # Boundary logic
        score = max(0, min(100, score))
        
        # Risk classification
        if score >= 80:
            risk_level = "Safe"
        elif score >= 50:
            risk_level = "Suspicious"
        else:
            risk_level = "Dangerous"
            
        return AnalysisResult(
            url=url_str,
            domain=domain,
            trust_score=score,
            risk_level=risk_level,
            factors=factors,
            details={
                "heuristics_score": score,
                "ssl_verified": ssl_info.get("valid", False),
                "ssl_issuer": ssl_info.get("issuer", "Unknown"),
                "domain_age_days": whois_info.get("age_days", -1),
                "ml_confidence": ml_confidence,
                "ml_prediction": ml_label
            }
        )
        
    except Exception as e:
        logger.error(f"Error executing analysis flow: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis engine failure: {str(e)}")

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "Sentinel AI Engine"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
