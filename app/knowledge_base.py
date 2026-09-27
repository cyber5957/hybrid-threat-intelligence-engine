from pydantic import BaseModel, Field
from datetime import datetime
import json
from pathlib import Path
from datetime import timezone

try:
    from .config import source_freshness, default_freshness
except ImportError:
    from config import source_freshness, default_freshness

# --- Models ---

class Evidence(BaseModel):
    ioc: str = Field(strict=True)
    ioc_type: str
    source: str
    finding: str
    verdict: str
    confidence: str
    timestamp: datetime
    reference: str

class KnownIOC(BaseModel):
    ioc: str = Field(strict=True)
    ioc_type: str
    current_verdict: str = "unknown"
    confidence: str = "none"
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

# --- Files ---
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
INPUT_FILE = DATA_DIR / "processed" / "ioc_results.json"
CACHE_DIR = DATA_DIR / "knowledge"
CACHED_FILE = CACHE_DIR / "demo_cached_knowledge.json"

# --- Type mapping from JSON keys ---

TYPE_MAP = {
    "IPs": "ip",
    "Domains": "domain",
    "URLs": "url",
    "Hashes": "hash",
}

# --- Load / Save ---

def load_knowledge_base():
    try:
        with CACHED_FILE.open(encoding="utf-8") as f:
            raw = json.load(f)
        return {k: KnownIOC.model_validate(v) for k, v in raw.items()}
    except FileNotFoundError:
        return {}

def save_knowledge_base(kb):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with CACHED_FILE.open("w", encoding="utf-8") as f:
        json.dump({k: v.model_dump(mode="json") for k, v in kb.items()}, f, indent=2)


def is_evidence_fresh(source: str, evidence_timestamp: datetime) -> bool:
    allowed_freshness = source_freshness.get(source, default_freshness)
    if evidence_timestamp.tzinfo is None:
        evidence_timestamp = evidence_timestamp.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - evidence_timestamp
    return age <= allowed_freshness

# --- Main ---

def process():
    kb = load_knowledge_base()

    with INPUT_FILE.open(encoding="utf-8") as f:
        data = json.load(f)

    now = datetime.now(timezone.utc)

    for key, ioc_list in data.items():
        ioc_type = TYPE_MAP.get(key, "unknown")

        for ioc in ioc_list:
            if ioc in kb:
                existing = kb[ioc]
                latest_evidence = existing.evidence[-1] if existing.evidence else None

                if latest_evidence and is_evidence_fresh(
                    latest_evidence.source,
                    latest_evidence.timestamp,
                ):
                    existing.last_seen = now
                    print(f"[KNOWN] {ioc} ({ioc_type})")
                else:
                    existing.last_seen = now
                    print(f"[KNOWN:STALE] {ioc} ({ioc_type})")
            else:
                kb[ioc] = KnownIOC(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    current_verdict="unknown",
                    confidence="none",
                    first_seen=now,
                    last_seen=now,
                    tags=[],
                    evidence=[]
                )
                print(f"[NEW]   {ioc} ({ioc_type})")

    save_knowledge_base(kb)
    print(f"\nDone. {len(kb)} total IoCs in cache.")

if __name__ == "__main__":
    process()
