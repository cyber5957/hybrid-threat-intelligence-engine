from datetime import timedelta

default_freshness = timedelta(days=7)

source_freshness = {
    "threat_intel_api": timedelta(days=3),
    "osint": timedelta(days=7),
    "analyst": timedelta(days=30),
}


