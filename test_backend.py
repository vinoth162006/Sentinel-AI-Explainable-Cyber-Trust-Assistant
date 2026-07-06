import sys
import os

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.ssl_checker import check_ssl_certificate
from utils.whois_checker import check_domain_age
from utils.content_analyzer import analyze_web_content
from ml_classifier import classifier

def run_tests():
    print("=" * 60)
    print("SENTINEL AI BACKEND UNIT TESTS")
    print("=" * 60)

    # Test 1: SSL Checker
    print("\n[Test 1] Testing SSL Certificate Checker...")
    try:
        ssl_res = check_ssl_certificate("google.com")
        print(f"  Google SSL Valid: {ssl_res['valid']}")
        print(f"  Google SSL Issuer: {ssl_res['issuer']}")
        print(f"  Google SSL Days Left: {ssl_res['days_to_expiry']}")
        assert ssl_res['valid'] is True, "Google SSL should be valid."
        print("  => SSL Check: PASS")
    except Exception as e:
        print(f"  => SSL Check: FAIL ({e})")

    # Test 2: WHOIS Checker
    print("\n[Test 2] Testing WHOIS Registry Checker...")
    try:
        whois_res = check_domain_age("google.com")
        print(f"  Google Age Days: {whois_res['age_days']}")
        print(f"  Google Registrar: {whois_res['registrar']}")
        print(f"  Google Is Young: {whois_res['is_young']}")
        assert whois_res['age_days'] > 365, "Google domain age should be greater than 1 year."
        print("  => WHOIS Check: PASS")
    except Exception as e:
        print(f"  => WHOIS Check: FAIL ({e})")

    # Test 3: ML Feature Extraction
    print("\n[Test 3] Testing ML Feature Extraction...")
    try:
        test_url = "http://secure.verification-portal-paypal.com/login?user=scam"
        features = classifier.extract_features(test_url)
        print(f"  URL Length: {features['url_length']}")
        print(f"  IP present: {features['is_ip']}")
        print(f"  Keyword count: {features['sensitive_keyword_count']}")
        print(f"  Subdomains: {features['subdomain_count']}")
        assert features['sensitive_keyword_count'] >= 2, "Keywords 'secure', 'verification', 'paypal', 'login' should trigger keywords count."
        print("  => ML Feature Extraction: PASS")
    except Exception as e:
        print(f"  => ML Feature Extraction: FAIL ({e})")

    # Test 4: ML Prediction Fallback
    print("\n[Test 4] Testing ML Phishing Classifier Predictions...")
    try:
        label, conf, _ = classifier.predict("https://google.com")
        print(f"  google.com classification: {label} (Conf: {conf:.1%})")
        
        phish_label, phish_conf, _ = classifier.predict("http://secure-login-chase-account-verify.tk/update")
        print(f"  Phishing URL classification: {phish_label} (Conf: {phish_conf:.1%})")
        
        assert label == "Safe", "Google should be predicted as Safe."
        assert phish_label in ["Phishing", "Suspicious"], "Malicious URL should be flagged."
        print("  => ML Classifier Check: PASS")
    except Exception as e:
        print(f"  => ML Classifier Check: FAIL ({e})")

    # Test 5: DOM Content Analyzer
    print("\n[Test 5] Testing DOM Content / Telemetry Analyzer...")
    try:
        mock_telemetry = {
            "hasPasswordForms": True,
            "insecurePasswordForm": True,
            "hiddenIframesCount": 2,
            "metaRedirectFound": True,
            "detectedBrandImpersonation": True
        }
        factors = analyze_web_content("paypal-security-signin.tk", mock_telemetry)
        print(f"  Telemetry Factors Extracted: {len(factors)}")
        for f in factors:
            print(f"    - [{f['status'].upper()}] {f['name']}: {f['desc']}")
            
        danger_factors = [f for f in factors if f["status"] == "danger"]
        assert len(danger_factors) >= 2, "Should detect Brand Impersonation and Insecure Passwords."
        print("  => DOM Content Analyzer Check: PASS")
    except Exception as e:
        print(f"  => DOM Content Analyzer Check: FAIL ({e})")

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
