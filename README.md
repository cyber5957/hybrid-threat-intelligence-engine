# Hybrid Threat Intelligence Engine

A Python project for extracting indicators of compromise (IOCs) from security alert text and maintaining a small, structured knowledge cache. The current demo focuses on IP addresses and domain-like indicators, using synthetic alert data reserved for documentation and testing.

> **Project status:** Early development. The IOC extraction and knowledge-cache scripts are implemented. `frontent/` contains a static analyst-interface preview with browser-side candidate extraction; it is not connected to the Python workflow. Risk scoring, machine learning, enrichment APIs, and a backend service are not implemented.

## Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Run the Demo](#run-the-demo)
- [Frontend Preview](#frontend-preview)
- [Data and Output](#data-and-output)
- [Project Layout](#project-layout)
- [Current Scope](#current-scope)
- [Roadmap](#roadmap)
- [Security Scope](#security-scope)

## What It Does

The demo workflow has two steps:

1. Extract candidate IP addresses and domains from the demo alert, validate them, and save the results as JSON.
2. Load those indicators into a Pydantic-validated knowledge cache, marking existing indicators as known and adding new ones.

The scripts support investigation workflows; they do not determine whether an indicator is malicious or take response actions.

## Quick Start

Requirements: Python 3.9 or newer and `pip`.

Create and activate a virtual environment from the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux, activate it with:

```bash
source .venv/bin/activate
```

Install the project dependency:

```bash
python -m pip install -r requirements.txt
```

The current dependency list contains Pydantic. The knowledge-base models use Pydantic v2 APIs.

## Run the Demo

Run these commands from the repository root:

```bash
python app/ioc_extractor.py
python app/knowledge_base.py
```

The first command loads `demo_alert` from `scripts/seed_demo_data.py`, extracts indicators from its description, prints the result, and writes `data/processed/ioc_results.json`. The second command reads that JSON, updates or creates records, and saves the cache to `data/knowledge/demo_cached_knowledge.json`.

The extractor can also be imported and called with alert text:

```python
from app.ioc_extractor import extract_iocs

results = extract_iocs("Suspicious connection to 198.51.100.42 at login.example.com")
```

Each extraction replaces the contents of `ioc_results.json` with the latest result.

## Frontend Preview

Open `frontent/index.html` in a browser to view the static analyst-interface preview. Its extraction runs locally in browser JavaScript and supports candidate IPv4 addresses and domains. It does not call `app/ioc_extractor.py`, read or update the Python knowledge cache, verify indicators, or calculate risk. Treat all results as unverified candidates.

## Data and Output

The extraction result has four keys to keep a consistent JSON shape:

```json
{
    "URLs": [],
    "IPs": ["198.51.100.42"],
    "Domains": ["login.example.com"],
    "Hashes": []
}
```

At present, only IP and domain extraction is implemented; `URLs` and `Hashes` are empty placeholders. The knowledge cache stores each indicator with its type, verdict, confidence, first- and last-seen timestamps, tags, and evidence. New records currently begin with an `unknown` verdict and `none` confidence.

The included demo uses synthetic indicators and `.example` domains. It is not a live threat feed and does not make a security verdict.

## Project Layout

```text
app/
    ioc_extractor.py       Extract and validate IP/domain indicators
    knowledge_base.py      Update the Pydantic-backed IOC cache
    schemas.py             Evidence model prototype
    config.py              Reserved for application configuration
    main.py                Reserved for an application entry point
    ml_model.py            Planned machine-learning component
    risk_rules.py          Planned rule-based scoring component
    llm_explainer.py       Planned explanation component
data/
    knowledge/             Cached IOC knowledge
    processed/             Extracted IOC results
    raw/                   Reserved for source data
scripts/
    seed_demo_data.py      Synthetic demo alert
    train_model.py         Reserved for model training
docs/                    Architecture, API, and threat-model docs
tests/                   Test package structure; automated tests are not yet present
models/                  Reserved for model artifacts
logs/                    Reserved for application logs
```

## Current Scope

| Capability | Status |
| --- | --- |
| Extract IPv4 candidates and validate octets | Implemented |
| Extract domain-like candidates and filter invalid labels | Implemented |
| Write extraction results to JSON | Implemented |
| Validate knowledge records with Pydantic | Implemented |
| Update first-seen/last-seen cache records | Implemented |
| Extract URLs and file hashes | Planned |
| Threat-feed enrichment and verdicting | Planned |
| Rule-based and machine-learning risk scoring | Planned |
| Static analyst-interface preview | Implemented (not connected to Python workflow) |
| FastAPI service or integrated analyst dashboard | Planned |
| Automated test coverage | Planned |

## Roadmap

- Add focused unit tests for extraction, validation, and cache updates.
- Expand indicator extraction to URLs and file hashes.
- Add evidence-backed threat-intelligence enrichment and explainable verdicts.
- Implement risk rules and evaluate a machine-learning approach against a documented dataset.
- Define service and analyst-interface requirements before adding an API or dashboard.

## Security Scope

This is a defensive analysis project. The included demo data is synthetic; the current scripts do not scan networks, execute files, block indicators, or perform incident-response actions. Treat all extracted values as unverified input until they are checked against trusted sources. Do not place credentials or API keys in source files; use local environment configuration when integrations are introduced.
