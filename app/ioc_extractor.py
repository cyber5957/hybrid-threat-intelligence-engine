import re
from urllib.parse import urlparse
import json
from pathlib import Path

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

# ─── Main Execution ───────────────────────────────────────────────

text = """User logged in successfully from the office network."""

results = extract_iocs(text)

# 1. Pretty-print to console (readable JSON)
print("=" * 50)
print("PRETTY JSON OUTPUT:")
print("=" * 50)
print(json.dumps(results, indent=2))

# 2. Save to one stable JSON file (for later use / FastAPI testing)
results_path = Path(__file__).resolve().parent.parent / "data" / "processed" / "ioc_results.json"
results_path.parent.mkdir(parents=True, exist_ok=True)

with open(results_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to '{results_path}'")

# 3. Read the JSON back (simulating another script/file reading it)
with open(results_path, "r") as f:
    loaded = json.load(f)

print("\n" + "=" * 50)
print("READ BACK FROM FILE:")
print("=" * 50)
print(f"Domains found: {loaded['Domains']}")
print(f"Hashes found:  {loaded['Hashes']}")
print(f"Total IOCs:    {sum(len(v) for v in loaded.values())}")