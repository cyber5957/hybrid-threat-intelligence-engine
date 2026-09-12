import json
from pathlib import Path


def calculate_risk(ioc_results):
     score = 0
     empty_findings_list = []
     empty_action_list = []
     risk_level = ""
     if ioc_results == {}:
                 print("fiindings: no ioc's fount in the alert")
                 print("action: no immediate action required; continue monitoring")
                 print("risk level: low")
     


results_path = Path(__file__).resolve().parent.parent / "data" / "processed" / "ioc_results.json"

with open(results_path, "r") as file:
        ioc_results = json.load(file)
        calculate_risk(ioc_results)
        print(ioc_results)
        
        
