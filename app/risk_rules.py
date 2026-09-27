"""Deterministic verdicts derived from collected provider evidence.

This module is the decision layer: it deliberately treats the language model as
an optional explanation aid and never accepts a model generated verdict.
"""
from __future__ import annotations

from typing import Any


def assess_evidence(results: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [item for item in results if item.get("status") in {"complete", "cached"}]
    adverse = [item for item in usable if item.get("verdict") in {"malicious", "suspicious"}]
    clean = [item for item in usable if item.get("verdict") == "clean"]
    scores = [int(item["risk_score"]) for item in usable if item.get("risk_score") is not None]

    if any(item.get("verdict") == "malicious" for item in adverse):
        verdict = "malicious"
        rationale = "At least one intelligence source reported malicious activity."
        confidence = "high" if len(adverse) > 1 else "medium"
    elif adverse:
        verdict = "suspicious"
        rationale = "At least one intelligence source reported suspicious activity."
        confidence = "medium" if len(adverse) > 1 else "low"
    elif usable and clean and len(clean) == len(usable):
        verdict = "clean"
        rationale = "All available reputation sources returned clean findings."
        confidence = "medium" if len(clean) > 1 else "low"
    else:
        verdict = "unknown"
        rationale = "Available evidence is inconclusive; unknown does not mean clean."
        confidence = "none"

    return {
        "verdict": verdict,
        "risk_score": max(scores) if scores else (0 if verdict == "clean" else None),
        "confidence": confidence,
        "evidence_count": len(usable),
        "sources": list(dict.fromkeys(item.get("provider", "unknown") for item in usable)),
        "rationale": rationale,
        "decision_source": "deterministic_rules",
    }
