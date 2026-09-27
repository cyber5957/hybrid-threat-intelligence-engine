"""Best-effort reputation lookups with API-key configuration and DB-backed caching."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from .database import connect

CACHE_TTL = timedelta(hours=6)
PROVIDER_KEYS = {
    "virustotal": "VIRUSTOTAL_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY", "shodan": "SHODAN_API_KEY",
}
RATE_INTERVAL_SECONDS = {"virustotal": 15.0, "abuseipdb": 1.0, "otx": 1.0, "shodan": 1.0}
_provider_locks = {name: asyncio.Semaphore(2) for name in PROVIDER_KEYS}
_provider_rate_locks = {name: asyncio.Lock() for name in PROVIDER_KEYS}
_provider_last_request: dict[str, float] = {}


def provider_status() -> dict[str, dict[str, Any]]:
    return {name: {"configured": bool(os.getenv(key)), "status": "ready" if os.getenv(key) else "not_configured"}
            for name, key in PROVIDER_KEYS.items()}


def _provider_url(ioc_type: str, value: str) -> tuple[str, str] | None:
    if ioc_type == "ipv4" or ioc_type == "ipv6": return "ip", value
    if ioc_type == "domain": return "domain", value
    if ioc_type == "url": return "url", value
    if ioc_type in {"md5", "sha1", "sha256"}: return "file", value
    if ioc_type == "cve": return "cve", value
    return None


def _normalize_result(provider: str, status: int, payload: Any) -> dict[str, Any]:
    verdict, score, summary = "unknown", None, "No reputation data returned"
    if status >= 400:
        return {"provider": provider, "verdict": verdict, "risk_score": score, "metadata": {"error": f"Provider returned HTTP {status}"}, "status": "error"}
    if provider == "virustotal":
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0)); suspicious = int(stats.get("suspicious", 0)); harmless = int(stats.get("harmless", 0))
        total = malicious + suspicious + harmless + int(stats.get("undetected", 0))
        score = round(100 * (malicious + suspicious * 0.5) / max(total, 1)) if total else None
        verdict = "malicious" if malicious else "suspicious" if suspicious else "clean" if harmless else "unknown"
        summary = f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless detections"
        payload = {"analysis_stats": stats, "reputation": payload.get("data", {}).get("attributes", {}).get("reputation")}
    elif provider == "abuseipdb":
        data = payload.get("data", {}); score = int(data.get("abuseConfidenceScore", 0));
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        summary = f"Abuse confidence {score}%"; payload = {k: data.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode", "isp", "domain", "lastReportedAt")}
    elif provider == "otx":
        pulses = payload.get("pulse_info", {}).get("count", 0)
        verdict = "suspicious" if pulses else "unknown"
        score = min(90, pulses * 20) if pulses else None; summary = f"Referenced in {pulses} OTX pulse(s)"
        payload = {"pulse_count": pulses, "sections": payload.get("sections", [])}
    elif provider == "shodan":
        ports = payload.get("ports", []); score = None
        verdict = "unknown"; summary = f"{len(ports)} exposed port(s) observed; exposure alone does not determine reputation"
        payload = {"ports": ports[:50], "country_code": payload.get("country_code"), "org": payload.get("org"), "last_update": payload.get("last_update")}
    return {"provider": provider, "verdict": verdict, "risk_score": score, "metadata": {"summary": summary, "data": payload}, "status": "complete"}


async def _request(provider: str, ioc_type: str, value: str) -> dict[str, Any] | None:
    key = os.getenv(PROVIDER_KEYS[provider])
    if not key: return None
    target = _provider_url(ioc_type, value)
    if not target: return None
    kind, safe_value = target
    headers = {}; params = {}; method = "GET"; body = None
    if provider == "virustotal":
        if kind == "url":
            safe_value = base64.urlsafe_b64encode(safe_value.encode()).decode().rstrip("=")
        endpoint = {"ip": f"ip_addresses/{quote(safe_value, safe=':')}", "domain": f"domains/{quote(safe_value)}", "url": f"urls/{quote(safe_value, safe='')}", "file": f"files/{quote(safe_value)}"}[kind]
        url = f"https://www.virustotal.com/api/v3/{endpoint}"; headers["x-apikey"] = key
    elif provider == "abuseipdb":
        if kind != "ip": return None
        url = "https://api.abuseipdb.com/api/v2/check"; headers["Key"] = key; headers["Accept"] = "application/json"; params = {"ipAddress": safe_value, "maxAgeInDays": "90"}
    elif provider == "otx":
        otx_type = "IPv4" if ioc_type == "ipv4" else "IPv6" if ioc_type == "ipv6" else "domain" if ioc_type == "domain" else "url" if kind == "url" else "cve" if kind == "cve" else "file"
        section = "general"; url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(safe_value, safe='')}/{section}"; headers["X-OTX-API-KEY"] = key
    else:
        if kind != "ip": return None
        url = f"https://api.shodan.io/shodan/host/{quote(safe_value, safe=':')}"; params["key"] = key
    try:
        async with _provider_rate_locks[provider]:
            now = asyncio.get_running_loop().time()
            wait_for = RATE_INTERVAL_SECONDS[provider] - (now - _provider_last_request.get(provider, 0.0))
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            _provider_last_request[provider] = asyncio.get_running_loop().time()
        async with _provider_locks[provider]:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
                response = await client.request(method, url, headers=headers, params=params, json=body)
        try: payload = response.json()
        except ValueError: payload = {}
        return _normalize_result(provider, response.status_code, payload)
    except (httpx.HTTPError, TimeoutError) as exc:
        return {"provider": provider, "verdict": "unknown", "risk_score": None, "metadata": {"error": str(exc)[:200]}, "status": "error"}


def _cached(ioc_id: int, cache_key: str) -> list[dict[str, Any]]:
    cutoff = (datetime.now(timezone.utc) - CACHE_TTL).isoformat()
    with connect() as db:
        rows = db.execute("SELECT provider,verdict,risk_score,metadata FROM enrichment_results WHERE indicator_id=? AND cache_key=? AND status<>'error' AND checked_at>=? ORDER BY id DESC", (ioc_id, cache_key, cutoff)).fetchall()
    return [{"provider": r["provider"], "verdict": r["verdict"], "risk_score": r["risk_score"], "metadata": json.loads(r["metadata"]), "status": "cached"} for r in rows]


async def enrich_one(ioc_id: int, ioc_type: str, value: str) -> list[dict[str, Any]]:
    cache_key = hashlib.sha256(f"{ioc_type}:{value.lower()}".encode()).hexdigest()
    cached = _cached(ioc_id, cache_key)
    cached_names = {item["provider"] for item in cached}
    pending = [name for name in PROVIDER_KEYS if os.getenv(PROVIDER_KEYS[name]) and name not in cached_names]
    if not pending: return cached
    results = await asyncio.gather(*(_request(provider, ioc_type, value) for provider in pending))
    fresh = [result for result in results if result]
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        for result in fresh:
            db.execute("INSERT INTO enrichment_results(indicator_id,provider,verdict,risk_score,metadata,status,checked_at,cache_key) VALUES(?,?,?,?,?,?,?,?)",
                       (ioc_id, result["provider"], result["verdict"], result["risk_score"], json.dumps(result["metadata"]), result.get("status", "complete"), now, cache_key))
    return cached + fresh


def aggregate(results: list[dict[str, Any]]) -> tuple[str, int | None]:
    usable = [r for r in results if r.get("status") != "error"]
    if not usable: return "unknown", None
    verdicts = [r["verdict"] for r in usable]
    scores = [int(r["risk_score"]) for r in usable if r.get("risk_score") is not None]
    score = max(scores) if scores else None
    if "malicious" in verdicts: return "malicious", score
    if "suspicious" in verdicts: return "suspicious", score
    if all(v == "clean" for v in verdicts): return "clean", score
    return "unknown", None
