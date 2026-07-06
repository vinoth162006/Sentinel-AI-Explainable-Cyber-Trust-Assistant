import logging
import urllib.parse
from typing import Dict, Any, List

logger = logging.getLogger("SentinelContent")

# High-risk keywords commonly used in scam or phishing websites
SCAM_KEYWORDS = ["win prize", "claim reward", "verify account now", "confirm password", "urgent update", "unusual activity detected", "bank logout", "giftcard winner"]

def analyze_web_content(domain: str, dom_telemetry: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Analyzes page structure, telemetry inputs, and brand elements to generate 
    risk explanation factors.
    """
    factors = []
    
    # If no DOM telemetry is provided, create a mock empty structure
    if dom_telemetry is None:
        dom_telemetry = {}
        
    # Extract telemetry values with fallbacks
    has_pwd_forms = dom_telemetry.get("hasPasswordForms", False)
    insecure_pwd_form = dom_telemetry.get("insecurePasswordForm", False)
    hidden_iframes_count = dom_telemetry.get("hiddenIframesCount", 0)
    meta_redirect = dom_telemetry.get("metaRedirectFound", False)
    brand_impersonation = dom_telemetry.get("detectedBrandImpersonation", False)
    
    # 1. Evaluate Brand Impersonation
    if brand_impersonation:
        factors.append({
            "status": "danger",
            "name": "Brand Impersonation Detected",
            "desc": "The page title mimics a prominent institution, but the domain hostname does not match. Likely a login spoof."
        })
        
    # 2. Evaluate Insecure Forms
    if has_pwd_forms:
        if insecure_pwd_form:
            factors.append({
                "status": "danger",
                "name": "Insecure Password Transmission",
                "desc": "Found credentials forms that submit data over insecure HTTP protocols. Susceptible to MITM interception."
            })
        else:
            factors.append({
                "status": "safe",
                "name": "Encrypted Form Controls",
                "desc": "Sign-in elements found are properly configured to transmit data over encrypted connections."
            })
            
    # 3. Evaluate Hidden Iframes
    if hidden_iframes_count > 0:
        factors.append({
            "status": "warning",
            "name": f"Hidden Iframes Present ({hidden_iframes_count})",
            "desc": "Invisible frames found in the document object model. Often used for silent redirects or clickjacking."
        })
        
    # 4. Evaluate Redirect Nodes
    if meta_redirect:
        factors.append({
            "status": "warning",
            "name": "Automatic Refresh Redirect",
            "desc": "The page includes meta tag commands that automatically force client-side page transitions."
        })
        
    return factors
