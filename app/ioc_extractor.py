import re


IP_PATTERN = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
DOMAIN_PATTERN = r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b"


def ip_validation(ip_addresses: list[str]) -> list[str]:
    """Return unique IPv4 addresses with valid octets."""
    valid_ips = []
    for ip_address in ip_addresses:
        try:
            octets = [int(value) for value in ip_address.split(".")]
        except ValueError:
            continue

        if len(octets) == 4 and all(0 <= value <= 255 for value in octets):
            valid_ips.append(ip_address)

    return list(dict.fromkeys(valid_ips))


def domain_extractor(domains: list[str]) -> list[str]:
    """Return domain-like values and exclude invalid labels and IPv4 addresses."""
    valid_domains = []
    for domain in domains:
        has_invalid_label = False
        for label in domain.split("."):
            if label.startswith("-") or label.endswith("-"):
                has_invalid_label = True
                break

        if has_invalid_label or domain.rsplit(".", 1)[-1].isdigit():
            continue

        valid_domains.append(domain)

    return valid_domains


def extract_iocs(alert: str) -> dict[str, list[str]]:
    """Extract and validate IP and domain indicators from an alert."""
    ip_candidates = re.findall(IP_PATTERN, alert)
    domain_candidates = re.findall(DOMAIN_PATTERN, alert)

    return {
        "ips": ip_validation(ip_candidates),
        "domains": domain_extractor(domain_candidates),
    }


if __name__ == "__main__":
    alert = """Source IP: 185.220.101.5
Connected to evil-example.com
Destination: 192.168.1.20
Visited login.evil-example.com"""

    print(extract_iocs(alert))