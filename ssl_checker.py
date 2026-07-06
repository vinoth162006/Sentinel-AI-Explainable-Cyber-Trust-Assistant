import datetime
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger("SentinelSSL")

def check_ssl_certificate(domain: str) -> dict:
    """
    Connects to the domain via SSL/TLS on port 443, extracts and verifies
    the certificate details.
    """
    result = {
        "valid": False,
        "issuer": "Unknown",
        "expiry_date": None,
        "days_to_expiry": -1,
        "subject": "Unknown",
        "error": None
    }
    
    # Strip any port number if present in domain
    if ":" in domain:
        domain = domain.split(":")[0]

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        # Establish connection to target host
        with socket.create_connection((domain, 443), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the binary certificate
                bin_cert = ssock.getpeercert(binary_form=True)
                
                # Parse using cryptography library
                cert = x509.load_der_x509_certificate(bin_cert, default_backend())
                
                # Extract Issuer and Subject
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                
                # Extract Issuer Common Name (CN) or Organization (O) for readable display
                issuer_cn = "Unknown"
                for attribute in cert.issuer:
                    if attribute.oid._name == "commonName" or attribute.oid._name == "organizationName":
                        issuer_cn = attribute.value
                        break
                
                # Check expiry dates
                not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
                now = datetime.datetime.now(datetime.timezone.utc) if not_after.tzinfo else datetime.datetime.now()
                
                days_left = (not_after - now).days
                
                result["valid"] = days_left > 0
                result["issuer"] = issuer_cn
                result["expiry_date"] = not_after.strftime("%Y-%m-%d %H:%M:%S")
                result["days_to_expiry"] = days_left
                result["subject"] = subject
                
                logger.info(f"SSL for {domain} is valid. Issued by: {issuer_cn}. Days left: {days_left}")
                
    except socket.timeout:
        result["error"] = "Connection timed out (Port 443 blocked or offline)."
        logger.warning(f"SSL timeout on domain: {domain}")
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL Certificate Verification Failed: {e.reason}"
        logger.warning(f"SSL cert verification error on domain: {domain} ({e.reason})")
    except Exception as e:
        result["error"] = f"SSL Error: {str(e)}"
        logger.warning(f"SSL connection failed on domain: {domain} ({str(e)})")
        
    return result

if __name__ == "__main__":
    # Test checking a known safe domain
    import json
    print(json.dumps(check_ssl_certificate("google.com"), indent=2))
