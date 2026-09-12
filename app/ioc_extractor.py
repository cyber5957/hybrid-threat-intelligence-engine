import re
from urllib.parse import urlparse

# Regex patterns with proper escaping
URL_RE = re.compile(r'https?://[^\s<>"\)\]]+')
IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')

def dedupe(items):
    
    seen = set()
    unique = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique

def domain_extractor(url):
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    return domain.rstrip('/')

def extract_iocs(text):
    """
    Extract unique URLs, IPs, domains, and MD5 hashes from text.
    Returns a dict with 4 clean lists ready for JSON/FastAPI.
    """
   
    urls = dedupe(URL_RE.findall(text))
    ips = dedupe(IP_RE.findall(text))
    hashes = dedupe(HASH_RE.findall(text))
    
    # Extract unique domains from URLs
    domains_set = set()
    for url in urls:
        domain = domain_extractor(url)
        if domain:
            domains_set.add(domain)
    
    
    return {
        "URLs": urls,
        "IPs": ips,
        "Domains": sorted(domains_set),  
        "Hashes": hashes,
    }

text = """Alert: User clicked https://secure-login-update.com/login
from IP 185.220.101.45. Hash: d41d8cd98f00b204e9800998ecf8427e"""

results = extract_iocs(text)
print(results)