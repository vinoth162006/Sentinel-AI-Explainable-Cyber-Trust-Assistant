import datetime
import whois
import logging

logger = logging.getLogger("SentinelWHOIS")

def check_domain_age(domain: str) -> dict:
    """
    Looks up the WHOIS registration records for a domain and evaluates its age.
    """
    result = {
        "age_days": -1,
        "creation_date": None,
        "registrar": "Unknown",
        "is_young": False,
        "error": None
    }
    
    # Clean domain name
    if domain.startswith("www."):
        domain = domain[4:]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    try:
        # Perform WHOIS lookup
        w = whois.whois(domain)
        
        # WHOIS library can return creation_date as a single datetime or list of datetimes
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            # Select the earliest creation date in the list
            creation_date = creation_date[0]
            
        if creation_date and isinstance(creation_date, datetime.datetime):
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            now = datetime.datetime.now()
            age = now - creation_date
            result["age_days"] = age.days
            result["creation_date"] = creation_date.strftime("%Y-%m-%d")
            
            # Domain is young if registered less than 180 days (6 months) ago
            result["is_young"] = age.days < 180
        else:
            result["error"] = "Creation date could not be parsed."
            
        if w.registrar:
            result["registrar"] = w.registrar
            
        logger.info(f"WHOIS check complete for {domain}. Age: {result['age_days']} days. Registrar: {result['registrar']}")
        
    except Exception as e:
        result["error"] = f"WHOIS Lookup failed: {str(e)}"
        logger.warning(f"WHOIS check failed for domain: {domain} ({str(e)})")
        
    return result

if __name__ == "__main__":
    # Test checking a known old domain
    import json
    print(json.dumps(check_domain_age("google.com"), indent=2))
