"""Evidence-grounded alert context helpers (heuristics are analyst leads, not attribution)."""
from __future__ import annotations

from typing import Any


ATTACK_HINTS = (
    ("T1566", "Phishing", ("phishing", "spearphish", "email lure")),
    ("T1105", "Ingress Tool Transfer", ("downloaded payload", "download tool", "payload transfer")),
    ("T1071.001", "Web Protocols", ("http command and control", "https command and control", "web protocol c2")),
)


def attack_hints(text: str) -> list[dict[str, Any]]:
    lowered = text.casefold()
    return [
        {"technique_id": technique_id, "name": name, "matched_terms": [term for term in terms if term in lowered],
         "source": "source_alert_text", "confidence": "low", "inference": True}
        for technique_id, name, terms in ATTACK_HINTS
        if any(term in lowered for term in terms)
    ]


def grounded_summary(providers: list[dict[str, Any]], indicator_count: int) -> dict[str, Any]:
    """Summarize recorded provider evidence without filling gaps with model-generated claims."""
    usable = [item for item in providers if item.get("status") in {"complete", "cached"}]
    malicious = sum(item.get("verdict") == "malicious" for item in usable)
    suspicious = sum(item.get("verdict") == "suspicious" for item in usable)
    clean = sum(item.get("verdict") == "clean" for item in usable)
    if malicious:
        summary = f"{malicious} provider finding(s) marked an indicator malicious. Review the provider evidence and affected systems."
    elif suspicious:
        summary = f"{suspicious} provider finding(s) marked an indicator suspicious. Validate the activity with local telemetry."
    elif usable and clean == len(usable):
        summary = "All currently usable provider findings were clean; this does not establish that the alert is benign."
    else:
        summary = "There is not enough usable provider evidence to assign a verdict. Unknown does not mean clean."
    actions = ["Correlate the indicators with endpoint, DNS, proxy, and authentication logs."]
    if not usable:
        actions.insert(0, "Configure a supported threat intelligence provider or review the indicators manually.")
    if malicious or suspicious:
        actions.insert(0, "Prioritize analyst review of the adverse provider findings.")
    return {"summary": summary, "indicator_count": indicator_count, "evidence_count": len(usable),
            "provider_counts": {"malicious": malicious, "suspicious": suspicious, "clean": clean},
            "recommended_actions": actions, "grounding": "recorded_provider_evidence"}
