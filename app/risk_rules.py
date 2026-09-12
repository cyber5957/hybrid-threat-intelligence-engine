import json
from pathlib import Path


def calculate_risk(ioc_results):
        score = 0
        findings = []
        recommended_actions = []
        risk_level = ""

        if all(not ioc_results.get(ioc_type, []) for ioc_type in ("URLs", "IPs", "Domains", "Hashes")):
                findings.append("No IOCs found in the alert")
                recommended_actions.append("No immediate action required; continue monitoring")
                risk_level = "Low"

        return {
                "risk_score": score,
                "risk_level": risk_level,
                "findings": findings,
                "recommended_actions": recommended_actions,
        }


results_path = Path(__file__).resolve().parent.parent / "data" / "processed" / "ioc_results.json"

with open(results_path, "r") as file:
        ioc_results = json.load(file)
        risk_result = calculate_risk(ioc_results)
        print(risk_result)

        
        
