import json
import logging
import math
import os
import re
import urllib.parse
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("SentinelML")

# Define lists of sensitive keywords and suspicious TLDs
SENSITIVE_KEYWORDS = ["login", "verify", "secure", "bank", "account", "signin", "update", "paypal", "netflix", "webscr", "ebayisapi", "free", "gift", "wallet", "crypto"]
SUSPICIOUS_TLDS = [".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".country", ".stream", ".men", ".work", ".click", ".top"]

# Path to the JSON weights file
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.json")

class PurePythonLogisticRegression:
    def __init__(self):
        self.weights = {}
        self.bias = 0.0
        self.feature_names = [
            "url_length", "hostname_length", "is_ip", "subdomain_count",
            "hyphen_count", "at_symbol_count", "slash_count", "suspicious_tld",
            "sensitive_keyword_count", "path_dash_count", "double_slash_path"
        ]
        
        # Load weights or use robust pre-configured defaults
        if not self.load_model():
            self._use_default_weights()

    def _use_default_weights(self):
        """
        Sets pre-calibrated default weights representing security logic:
        Positive weights mean higher probability of PHISHING.
        Negative weights mean higher probability of SAFE.
        """
        logger.info("Initializing ML Classifier with preset weights.")
        self.weights = {
            "url_length": 0.005,                # Long URLs are slightly suspicious
            "hostname_length": 0.01,            # Long hostnames are slightly suspicious
            "is_ip": 1.5,                       # IP hostnames are highly suspicious (+1.5)
            "subdomain_count": 0.25,            # Deep subdomains are suspicious
            "hyphen_count": 0.15,               # Domain hyphens are suspicious (typosquatting)
            "at_symbol_count": 1.2,             # At symbol redirects are highly suspicious (+1.2)
            "slash_count": 0.08,                # Deep path structures
            "suspicious_tld": 1.1,              # Zip, Tk, etc. (+1.1)
            "sensitive_keyword_count": 0.85,    # Phishing terms like 'login', 'paypal' (+0.85 per kw)
            "path_dash_count": 0.12,            # Hyphenations in subfolders
            "double_slash_path": 0.9            # redirectional bypasses (+0.9)
        }
        self.bias = -2.5 # Negative bias ensures benign URLs start with low phishing probability

    def sigmoid(self, z: float) -> float:
        try:
            return 1.0 / (1.0 + math.exp(-z))
        except OverflowError:
            return 0.0 if z < 0 else 1.0

    def load_model(self) -> bool:
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "r") as f:
                    data = json.load(f)
                    self.weights = data["weights"]
                    self.bias = data["bias"]
                    self.feature_names = data["feature_names"]
                logger.info(f"Loaded trained ML weights from {MODEL_PATH}")
                return True
            except Exception as e:
                logger.error(f"Error loading JSON model: {e}")
        else:
            logger.warning(f"No trained model at {MODEL_PATH}. Initializing preset defaults.")
        return False

    def save_model(self, filepath: str):
        data = {
            "weights": self.weights,
            "bias": self.bias,
            "feature_names": self.feature_names
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved trained ML model parameters to {filepath}")

    def extract_features(self, url_str: str) -> Dict[str, float]:
        """
        Extracts structural features from a URL.
        """
        features = {}
        try:
            parsed = urllib.parse.urlparse(url_str)
            domain = parsed.hostname or parsed.path.split('/')[0] or ""
            path = parsed.path or ""
        except Exception:
            domain = ""
            path = ""

        # Feature 1: URL Length
        features["url_length"] = float(len(url_str))
        
        # Feature 2: Hostname Length
        features["hostname_length"] = float(len(domain))
        
        # Feature 3: IP Address Host (0 or 1)
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        features["is_ip"] = 1.0 if re.match(ip_pattern, domain) else 0.0
        
        # Feature 4: Subdomain Count
        subdomains = domain.split('.')
        features["subdomain_count"] = float(len(subdomains))
        
        # Feature 5: Hyphen count in hostname
        features["hyphen_count"] = float(domain.count('-'))
        
        # Feature 6: '@' symbol in URL
        features["at_symbol_count"] = float(url_str.count('@'))
        
        # Feature 7: '/' symbol count in URL path
        features["slash_count"] = float(path.count('/'))
        
        # Feature 8: Presence of suspicious TLD (0 or 1)
        has_susp_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        features["suspicious_tld"] = 1.0 if has_susp_tld else 0.0
        
        # Feature 9: Count of sensitive phishing keywords in the URL
        keyword_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in url_str.lower())
        features["sensitive_keyword_count"] = float(keyword_count)
        
        # Feature 10: Dash count in path
        features["path_dash_count"] = float(path.count('-'))
        
        # Feature 11: Double slash presence in path (0 or 1)
        features["double_slash_path"] = 1.0 if "//" in path else 0.0

        return features

    def predict(self, url: str) -> Tuple[str, float, Dict[str, float]]:
        """
        Predicts if a URL is Phishing, Suspicious, or Safe.
        Returns:
            Tuple[label, confidence_score, feature_dict]
        """
        features_dict = self.extract_features(url)
        
        # Calculate z = sum(w_i * x_i) + bias
        z = self.bias
        for name in self.feature_names:
            z += self.weights.get(name, 0.0) * features_dict.get(name, 0.0)
            
        prob_phishing = self.sigmoid(z)
        
        if prob_phishing > 0.7:
            label = "Phishing"
            confidence = prob_phishing
        elif prob_phishing > 0.4:
            label = "Suspicious"
            confidence = prob_phishing
        else:
            label = "Safe"
            confidence = 1.0 - prob_phishing
            
        return label, confidence, features_dict

# Singleton instance
classifier = PurePythonLogisticRegression()
