import re
from urllib.parse import urlparse


def extract_iocs(text):
    urls  = re.findall(r'[\w.-]+://[\w.,-]+', text)
    ips   = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', text)

    def dedupe(items):
        seen, unique = set(), []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    results = {
        "URL":  dedupe(urls),
        "IP":   dedupe(ips),
        "Hash": dedupe(hashes),
    }

    for label, items in results.items():
        for item in items:
            print(f"{label}: {item}")

    print("NO HASH" if not results["Hash"] else f"hash values: {results['Hash']}")

    return results   


def domain_extractor(url):
    return urlparse(url).netloc


text = """Alert: User clicked http://secure-login-update.com from IP 185.220.101.45.
Firewall: blocked 185.220.101.45 outbound."""

iocs = extract_iocs(text)

print("--- domains ---")
for url in iocs["URL"]:
    print(domain_extractor(url))