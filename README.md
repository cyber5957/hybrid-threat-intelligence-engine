# Hybrid ML + LLM Threat Intelligence Engine

A final-year cybersecurity project that helps SOC analysts investigate suspicious alerts and threat reports.

The system extracts Indicators of Compromise (IOCs), such as IP addresses, URLs, domains, and file hashes. It then combines SOC detection rules, machine-learning risk scoring, and trusted threat-intelligence context to produce a clear analyst-friendly risk assessment.

## Project Objective

Security teams receive large numbers of alerts every day. Manually reviewing every indicator is slow and can lead to missed threats.

This project aims to support a SOC analyst by:

- Extracting IOCs from alert text and threat reports
- Identifying suspicious indicators
- Calculating a Low, Medium, or High risk level
- Using a machine-learning model to improve risk prediction
- Providing source-grounded AI-assisted explanations
- Recommending safe next actions for investigation and incident response

The system supports human analysts. It does not automatically block systems or make final security decisions.

## Planned Features

- IOC extraction for URLs, IP addresses, domains, and file hashes
- Rule-based SOC risk scoring
- ML-based malicious indicator classification
- Combined risk score and confidence level
- Trusted threat-intelligence knowledge base
- Grounded LLM explanation of findings
- FastAPI backend
- Streamlit analyst dashboard
- Audit logging and input validation

## Architecture

```text
Alert Text or IOC Input
          ↓
IOC Extraction
          ↓
SOC Rules + ML Risk Prediction
          ↓
Combined Risk Score
          ↓
Threat Knowledge Retrieval
          ↓
Grounded AI Explanation
          ↓
SOC Analyst Dashboard
```

## Technology Stack

- Python
- FastAPI
- Uvicorn
- Pandas
- Scikit-learn
- Streamlit
- XGBoost or Random Forest
- JSON / CSV datasets
- Git and GitHub

## Project Structure

```text
app/        Main application modules
data/       Raw, processed, and threat-intelligence data
models/     Saved machine-learning models
tests/      Automated tests
docs/       Architecture, API, and threat-model documentation
scripts/    Training and demo-data helper scripts
logs/       Safe audit logs for the application
```

## Current Development Status

The project repository, Python environment, GitHub version control, and folder structure have been created.

Next development milestone: build the IOC extraction module.

## Security and Ethical Scope

This is a defensive cybersecurity project.

- It uses safe datasets and simulated alert data.
- It does not scan systems without authorization.
- It does not execute malware or exploit vulnerabilities.
- API keys and secrets are stored locally in `.env` and are not uploaded to GitHub.
- AI-generated explanations must be based on trusted retrieved information and should clearly state uncertainty when evidence is insufficient.

## Team

- Team Member 1 - Project integration, backend, and SOC workflow
- Team Member 2 - Dataset preparation, testing, and ML evaluation
- Team Member 3 - Dashboard, documentation, and knowledge-base support

## Future Scope

- STIX/TAXII threat-feed integration
- Live threat-intelligence enrichment
- Docker deployment
- SIEM integration
- Analyst feedback loop for model improvement
- Role-based access control
