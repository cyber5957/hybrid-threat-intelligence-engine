"""IOC extraction backed by iocextract, with CVE/domain supplementation."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

import iocextract

DOMAIN_RE = re.compile(r"(?<![\w@])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
IPV4_TOKEN_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,63}(?![\w.-])")


def _lib_values(function_name: str, text: str) -> list[str]:
    fn = getattr(iocextract, function_name, None)
    if not fn:
        return []
    try:
        return [str(value).strip() for value in fn(text, refang=True) if str(value).strip()]
    except TypeError:
        return [str(value).strip() for value in fn(text) if str(value).strip()]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def extract_indicators(text: str) -> list[dict[str, str]]:
    """Extract, refang, validate and type supported indicators from alert text."""
    normalized = text.replace("[.]", ".").replace("(.)", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    candidates: dict[str, list[str]] = defaultdict(list)

    valid_ipv4_tokens = []
    for value in IPV4_TOKEN_RE.findall(normalized):
        try:
            parsed = ipaddress.ip_address(value)
            if parsed.version == 4:
                valid_ipv4_tokens.append(parsed.compressed)
        except ValueError:
            continue
    library_ipv4_values = _lib_values("extract_ipv4s", text) + _lib_values("extract_ipv4s", normalized)
    ipv4_values = [value for value in library_ipv4_values if value in valid_ipv4_tokens] + valid_ipv4_tokens
    ipv6_values = _lib_values("extract_ipv6s", text) + _lib_values("extract_ipv6s", normalized)
    for value in ipv4_values + ipv6_values:
        try:
            parsed = ipaddress.ip_address(value)
            candidates["ipv4" if parsed.version == 4 else "ipv6"].append(parsed.compressed)
        except ValueError:
            continue

    urls = _lib_values("extract_urls", text) + _lib_values("extract_urls", normalized)
    clean_urls = []
    for url in urls:
        url = url.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://").rstrip(".,;!?)\\\"'")
        if re.match(r"^https?://", url, re.IGNORECASE):
            clean_urls.append(url)
    candidates["url"].extend(clean_urls)

    for value in _lib_values("extract_hashes", text) + HASH_RE.findall(text):
        size = len(value)
        if size in (32, 40, 64) and re.fullmatch(r"[a-fA-F0-9]+", value):
            candidates[{32: "md5", 40: "sha1", 64: "sha256"}[size]].append(value.lower())
    normalized_emails = EMAIL_RE.findall(normalized)
    candidates["email"].extend(value for value in _lib_values("extract_emails", text) if value in normalized_emails)
    candidates["email"].extend(normalized_emails)
    candidates["cve"].extend(match.upper() for match in CVE_RE.findall(text))

    urls_hosts = set()
    for url in candidates["url"]:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0].lower()
        urls_hosts.add(host)
    for domain in DOMAIN_RE.findall(normalized):
        domain = domain.lower().rstrip(".")
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        if domain not in urls_hosts:
            candidates["domain"].append(domain)

    output = []
    for kind in ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve", "email"):
        for value in _unique(candidates[kind]):
            output.append({"type": kind, "value": value})
    return output
